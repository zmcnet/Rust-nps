//! 定向测试：独立字节样例 + 双会话多流双向大流量 + 超窗/慢流 + 关闭唤醒
//!
//! 不依赖真实 Go 进程；字节样例按 nps-mux 源码逐字段核对。
//! 真实 Go npc 端到端互通由父代理在更高层联调验证。

use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{duplex, AsyncRead, AsyncWriteExt, ReadBuf};

fn msg(id: i32, content: &[u8]) -> MuxFrame {
    MuxFrame {
        flag: MUX_NEW_MSG,
        id,
        content: Some(content.to_vec()),
        window: None,
    }
}

fn msg_part(id: i32, content: &[u8]) -> MuxFrame {
    MuxFrame {
        flag: MUX_NEW_MSG_PART,
        id,
        content: Some(content.to_vec()),
        window: None,
    }
}

async fn inject(peer: &mut tokio::io::DuplexStream, frame: &MuxFrame) {
    peer.write_all(&frame.encode()).await.unwrap();
}

/// 读取对端帧，跳过会话自动发出的 ping / ping 回包
async fn next_frame(peer: &mut tokio::io::DuplexStream) -> MuxFrame {
    loop {
        let f = tokio::time::timeout(Duration::from_secs(5), MuxFrame::decode(peer))
            .await
            .expect("等待对端帧超时")
            .unwrap()
            .unwrap();
        if f.flag != MUX_PING_FLAG && f.flag != MUX_PING_RETURN {
            return f;
        }
    }
}

/// 读取下一帧（不过滤 ping），用于需要断言 ping 回包的场景
async fn next_any_frame(peer: &mut tokio::io::DuplexStream) -> MuxFrame {
    tokio::time::timeout(Duration::from_secs(5), MuxFrame::decode(peer))
        .await
        .expect("等待帧超时")
        .unwrap()
        .unwrap()
}

/// 读到指定 flag 的帧为止，途中的其它帧（自动 sendOk / ConnClose / ping）一律丢弃。
///
/// 会话的所有出站帧共用同一条 FIFO（`ConnClose` 刻意排在已入队数据之后，
/// 与 Go 行为一致），所以测试**不能**假设“下一帧就是我要的那帧”，
/// 否则断言会随控制帧的排队顺序抖动。
async fn next_frame_matching(peer: &mut tokio::io::DuplexStream, flag: u8) -> MuxFrame {
    for _ in 0..100_000 {
        let f = next_any_frame(peer).await;
        if f.flag == flag {
            return f;
        }
    }
    panic!("未等到 flag={flag} 的帧");
}

/// 读取恰好 `want` 字节，返回累计数据
async fn read_exact_stream(half: &mut MuxRecvHalf, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want);
    while out.len() < want {
        let chunk = tokio::time::timeout(Duration::from_secs(30), half.recv_data())
            .await
            .expect("等待子流数据超时");
        match chunk {
            Some(d) => out.extend_from_slice(&d),
            None => break,
        }
    }
    out
}

#[test]
fn constants_match_go_commit() {
    assert_eq!(MAXIMUM_SEGMENT_SIZE, 4085);
    assert_eq!(INITIAL_WINDOW, 4085 * 30);
    assert_eq!(INITIAL_WINDOW, 122_550);
    assert_eq!(MAX_WINDOW_SIZE, 1 << 27);
}

#[test]
fn window_pack_unpack_go_layout() {
    let v = pack_window(100, 5, true);
    assert_eq!(v, (1u64 << 63) | (100u64 << 32) | 5);
    assert_eq!(unpack_window(v), (100, 5, true));

    // 31 位掩码：wait 位不应混入 maxSize / read
    let v = pack_window(0x8000_0001, 0x9FFF_FFFF, false);
    assert_eq!(unpack_window(v), (1, 0x1FFF_FFFF, false));
}

#[tokio::test]
async fn decode_independent_byte_samples() {
    // muxNewMsg id=1 len=5 "hello"
    let bytes: &[u8] = &[3, 1, 0, 0, 0, 5, 0, b'h', b'e', b'l', b'l', b'o'];
    let mut cursor = bytes;
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!(f.flag, MUX_NEW_MSG);
    assert_eq!(f.id, 1);
    assert_eq!(f.content.as_deref(), Some(b"hello".as_ref()));

    // muxMsgSendOk id=2 window=0x7fff_ffff_0000_0005
    let bytes: &[u8] = &[5, 2, 0, 0, 0, 5, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f];
    let mut cursor = bytes;
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!(f.flag, MUX_MSG_SEND_OK);
    assert_eq!(f.id, 2);
    let (max, read, wait) = MuxFrame::unpack_window(f.window.unwrap());
    assert_eq!((max, read, wait), (0x7FFF_FFFF, 5, false));

    // muxNewConn id=-7（0xFFFFFFF9 LE），仅 5 字节帧头
    let bytes: &[u8] = &[6, 0xf9, 0xff, 0xff, 0xff];
    let mut cursor = bytes;
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!(f.flag, MUX_NEW_CONN);
    assert_eq!(f.id, -7);

    // muxPingFlag id=-1，内容 "x"
    let bytes: &[u8] = &[0, 0xff, 0xff, 0xff, 0xff, 1, 0, b'x'];
    let mut cursor = bytes;
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!(f.flag, MUX_PING_FLAG);
    assert_eq!(f.id, MUX_PING_ID);
    assert_eq!(f.content.as_deref(), Some(b"x".as_ref()));

    // 编码布局独立核对（不是 encode→decode 自证）
    let f = MuxFrame {
        flag: MUX_NEW_CONN_OK,
        id: 9,
        content: None,
        window: None,
    };
    assert_eq!(f.encode(), vec![1, 9, 0, 0, 0]);
    let f = msg(513, b"ab");
    assert_eq!(f.encode(), vec![3, 1, 2, 0, 0, 2, 0, b'a', b'b']);
    // sendOk 的 13 字节布局
    let f = MuxFrame::send_ok(4, 122_550, 4085, false);
    let mut expect = vec![5, 4, 0, 0, 0];
    expect.extend_from_slice(&pack_window(122_550, 4085, false).to_le_bytes());
    assert_eq!(f.encode(), expect);
}

#[tokio::test]
async fn decode_rejects_invalid_frames() {
    // 未知 flag
    let mut cursor: &[u8] = &[99, 0, 0, 0, 0];
    assert!(MuxFrame::decode(&mut cursor).await.is_err());

    // 内容长度 4086 > 4085（0x0FF6 LE）
    let mut cursor: &[u8] = &[3, 1, 0, 0, 0, 0xf6, 0x0f];
    assert!(MuxFrame::decode(&mut cursor).await.is_err());

    // 半帧 EOF：声明 5 字节但只给 3 字节
    let mut cursor: &[u8] = &[3, 1, 0, 0, 0, 5, 0, b'a', b'b', b'c'];
    assert!(MuxFrame::decode(&mut cursor).await.is_err());

    // 半帧头 EOF
    let mut cursor: &[u8] = &[3, 1, 0, 0];
    assert!(MuxFrame::decode(&mut cursor).await.is_err());

    // sendOk 半帧（只有 4/8 窗口字节）
    let mut cursor: &[u8] = &[5, 2, 0, 0, 0, 1, 2, 3, 4];
    assert!(MuxFrame::decode(&mut cursor).await.is_err());

    // 帧边界处干净 EOF → Ok(None)
    let mut cursor: &[u8] = &[];
    assert!(MuxFrame::decode(&mut cursor).await.unwrap().is_none());
}

/// 两个真实会话、4 条流、双向各 320KiB（合计 >1MiB），
/// 底层缓冲区只给 32KiB，强制全程做窗口滑动与 SendOk 确认。
#[tokio::test]
async fn two_sessions_multistream_bidirectional_over_1mib() {
    let (a, b) = duplex(32 * 1024);
    let s_a = Arc::new(MuxSession::new(a));
    let s_b = Arc::new(MuxSession::new(b));

    const STREAMS: usize = 4;
    const PER_STREAM: usize = 320 * 1024; // 4 × 320KiB × 2 方向 ≈ 2.5MiB

    let mut open_a = Vec::new();
    for _ in 0..STREAMS {
        open_a.push(s_a.open_stream().await.unwrap());
    }
    let mut accept_b = Vec::new();
    for _ in 0..STREAMS {
        accept_b.push(s_b.accept_stream().await.unwrap());
    }
    let ids_a: Vec<i32> = open_a.iter().map(|s| s.id()).collect();
    let ids_b: Vec<i32> = accept_b.iter().map(|s| s.id()).collect();
    assert_eq!(ids_a, ids_b, "两会话的子流 id 应对称");

    let mut tasks = Vec::new();
    for (sa, sb) in open_a.into_iter().zip(accept_b.into_iter()) {
        tasks.push(tokio::spawn(async move {
            let id = sa.id();
            let payload_a: Vec<u8> = (0..PER_STREAM).map(|i| (i % 251) as u8).collect();
            let payload_b: Vec<u8> = (0..PER_STREAM).map(|i| 255 - (i % 251) as u8).collect();

            let (mut w_a, mut r_a) = sa.into_split();
            let (mut w_b, mut r_b) = sb.into_split();

            // 双向并发写
            let pa = payload_a.clone();
            let pb = payload_b.clone();
            let writer_a = tokio::spawn(async move {
                w_a.send_data(&pa).await.unwrap();
                w_a
            });
            let writer_b = tokio::spawn(async move {
                w_b.send_data(&pb).await.unwrap();
                w_b
            });

            // 双向并发读
            let reader_b =
                tokio::spawn(async move { read_exact_stream(&mut r_b, PER_STREAM).await });
            let reader_a =
                tokio::spawn(async move { read_exact_stream(&mut r_a, PER_STREAM).await });

            let got_b = reader_b.await.unwrap();
            let got_a = reader_a.await.unwrap();
            let _ = writer_a.await.unwrap();
            let _ = writer_b.await.unwrap();

            assert_eq!(got_b.len(), PER_STREAM, "stream {id} A->B 截断");
            assert_eq!(got_b, payload_a, "stream {id} A->B 内容不一致");
            assert_eq!(got_a.len(), PER_STREAM, "stream {id} B->A 截断");
            assert_eq!(got_a, payload_b, "stream {id} B->A 内容不一致");
        }));
    }

    for t in tasks {
        tokio::time::timeout(Duration::from_secs(90), t)
            .await
            .expect("传输超时")
            .expect("传输任务 panic");
    }
    s_a.close();
    s_b.close();
    assert!(s_a.is_closed() && s_b.is_closed());
}

/// 发送超过初始窗口、且收不到任何 SendOk 时必须阻塞（不能无界堆积）。
#[tokio::test]
async fn send_window_blocks_when_no_send_ok() {
    let (a, mut peer) = duplex(1024 * 1024);
    let session = MuxSession::new(a);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 1,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    let ok = next_frame(&mut peer).await;
    assert_eq!((ok.flag, ok.id), (MUX_NEW_CONN_OK, 1));

    // 发送 3 倍初始窗口的数据，但对端（本测试）从不回 SendOk
    const TOTAL: usize = INITIAL_WINDOW as usize * 3;
    let payload = vec![0x7Eu8; TOTAL];
    let writer = tokio::spawn(async move { stream.send_data(&payload).await });

    // 只应收到恰好初始窗口那么多字节，且分片不超过 4085
    let mut received = 0usize;
    while received < INITIAL_WINDOW as usize {
        let f = next_frame(&mut peer).await;
        if f.flag == MUX_NEW_MSG || f.flag == MUX_NEW_MSG_PART {
            let n = f.content.as_ref().unwrap().len();
            assert!(n <= MAXIMUM_SEGMENT_SIZE, "单帧 {n}B 超过 4085");
            received += n;
        }
    }
    assert_eq!(
        received, INITIAL_WINDOW as usize,
        "发送量应恰好等于初始窗口"
    );

    // 窗口耗尽后写任务必须停在原地（不会继续产出帧）
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!writer.is_finished(), "窗口耗尽时发送未阻塞");

    // 再多读一点，确认没有更多数据帧偷偷到达
    let extra = tokio::time::timeout(Duration::from_millis(200), MuxFrame::decode(&mut peer)).await;
    if let Ok(Ok(Some(f))) = extra {
        assert!(
            f.flag != MUX_NEW_MSG && f.flag != MUX_NEW_MSG_PART,
            "超窗后仍收到数据帧"
        );
    }

    // 关闭会话必须解除阻塞（返回错误，而不是永久挂起）
    session.close();
    let res = tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .expect("关闭会话未解除发送阻塞")
        .unwrap();
    assert!(res.is_err(), "关闭后 send_data 应返回错误");
}

/// 超窗后收到对端 SendOk 必须恢复发送（真实的窗口滑动，而不是只阻塞）。
#[tokio::test]
async fn send_window_resumes_after_send_ok() {
    let (a, mut peer) = duplex(1024 * 1024);
    let session = MuxSession::new(a);

    // 会话主动开流；本测试扮演对端，回 NewConnOk
    let opener = tokio::spawn({
        let session = Arc::new(session);
        let s = Arc::clone(&session);
        async move {
            let stream = s.open_stream().await.unwrap();
            (stream, session, s)
        }
    });

    let new_conn = next_frame(&mut peer).await;
    assert_eq!(new_conn.flag, MUX_NEW_CONN);
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN_OK,
            id: new_conn.id,
            content: None,
            window: None,
        },
    )
    .await;

    let (mut stream, session, _keep) = opener.await.unwrap();
    let id = stream.id();
    assert_eq!(id, new_conn.id);

    const TOTAL: usize = INITIAL_WINDOW as usize + 20_000;
    let writer = tokio::spawn(async move {
        stream.send_data(&vec![0x5Au8; TOTAL]).await.unwrap();
        stream
    });

    // 读满初始窗口（不确认）
    let mut got = 0usize;
    while got < INITIAL_WINDOW as usize {
        let f = next_frame(&mut peer).await;
        if f.flag == MUX_NEW_MSG || f.flag == MUX_NEW_MSG_PART {
            got += f.content.as_ref().unwrap().len();
        }
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!writer.is_finished(), "窗口耗尽后应停止发送");

    // 对端确认已消费初始窗口全部数据 → 发送方必须继续
    inject(
        &mut peer,
        &MuxFrame::send_ok(id, INITIAL_WINDOW, INITIAL_WINDOW, false),
    )
    .await;

    let mut rest = 0usize;
    while rest < TOTAL - INITIAL_WINDOW as usize {
        let f = next_frame(&mut peer).await;
        if f.flag == MUX_NEW_MSG || f.flag == MUX_NEW_MSG_PART {
            rest += f.content.as_ref().unwrap().len();
        }
    }
    assert_eq!(rest, TOTAL - INITIAL_WINDOW as usize);
    let mut stream = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("窗口恢复后发送未完成")
        .unwrap();
    stream.close();
    session.close();
}

/// ping 负载必须是 Go `time.Time.MarshalText()` 风格的 RFC3339Nano 文本
/// （对端会 UnmarshalText 该内容；也绝不能是空负载）。
#[test]
fn ping_payload_is_rfc3339_text() {
    // 1970-01-01T00:00:00Z
    assert_eq!(rfc3339_from_unix(0, 0), "1970-01-01T00:00:00.000000000Z");
    // 2020-09-13T12:26:40Z
    assert_eq!(
        rfc3339_from_unix(1_600_000_000, 123_456_789),
        "2020-09-13T12:26:40.123456789Z"
    );
    // 闰日 + 负偏移（早于纪元）不应 panic
    let leap = rfc3339_from_unix(1_582_934_400, 0);
    assert!(leap.starts_with("2020-02-29T"), "got {leap}");
    let _ = rfc3339_from_unix(-1, 0);

    // 实际生成的负载可被 Go 的 RFC3339 解析器接受（形态检查）
    let now = rfc3339_now();
    assert!(now.ends_with('Z') && now.len() == 30, "got {now}");
    assert_eq!(&now[4..5], "-");
    assert_eq!(&now[10..11], "T");
}

/// 一条不消费数据的慢子流不能堵住会话 reader（其它帧仍能被处理）。
#[tokio::test]
async fn slow_stream_does_not_block_session_reader() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 1,
            content: None,
            window: None,
        },
    )
    .await;
    let mut slow = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    // 对端持续灌数据直到超过每流字节预算（我们从不读取 slow）
    let one = vec![0x11u8; MAXIMUM_SEGMENT_SIZE];
    let target = RECV_BYTE_CAP as usize + 4 * MAXIMUM_SEGMENT_SIZE;
    let mut sent = 0usize;
    while sent < target {
        // 使用 try_write 风格：duplex 有缓冲上限，写满即切回非阻塞推进 reader
        let frame = msg_part(1, &one);
        let bytes = frame.encode();
        match tokio::time::timeout(Duration::from_millis(200), peer.write_all(&bytes)).await {
            Ok(Ok(())) => sent += MAXIMUM_SEGMENT_SIZE,
            Ok(Err(_)) => break,
            Err(_) => break, // 对端（本会话）已停止读取该流数据，缓冲区满
        }
    }
    assert!(sent > 0);

    // 会话 reader 必须仍然存活：注入 ping 能收到回包
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_PING_FLAG,
            id: MUX_PING_ID,
            content: Some(b"p".to_vec()),
            window: None,
        },
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut alive = false;
    while Instant::now() < deadline {
        let f = next_any_frame(&mut peer).await;
        if f.flag == MUX_PING_RETURN {
            alive = true;
            break;
        }
    }
    assert!(alive, "会话 reader 被慢子流阻塞");

    // 慢流最终应被关闭（超预算），读取先耗尽已入队数据后返回 None
    let mut drained = 0usize;
    while let Some(d) = tokio::time::timeout(Duration::from_secs(5), slow.recv_data())
        .await
        .expect("慢流未被关闭，recv_data 永久挂起")
    {
        drained += d.len();
        assert!(drained <= RECV_BYTE_CAP as usize, "接收超过字节预算");
    }
    session.close();
}

/// 对端伪造 `read > sent` 的 SendOk 必须被忽略（不得下溢或 panic）。
#[tokio::test]
async fn illegal_send_ok_is_ignored() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 3,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    // 未发送任何数据，却宣称已确认 1MiB
    inject(
        &mut peer,
        &MuxFrame::send_ok(3, MAX_WINDOW_SIZE, 1 << 20, false),
    )
    .await;
    // 再注入超范围窗口值
    let huge = pack_window(0xFFFF_FFFF, 0xFFFF_FFFF, true);
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_MSG_SEND_OK,
            id: 3,
            content: None,
            window: Some(huge),
        },
    )
    .await;

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_PING_FLAG,
            id: MUX_PING_ID,
            content: None,
            window: None,
        },
    )
    .await;
    let mut saw_pong = false;
    for _ in 0..32 {
        if next_any_frame(&mut peer).await.flag == MUX_PING_RETURN {
            saw_pong = true;
            break;
        }
    }
    assert!(saw_pong, "reader 应存活");

    // 之后正常发送仍然可用（窗口未被破坏成 0 或溢出成大值）
    stream.send_data(b"still-works").await.unwrap();
    let f = next_frame(&mut peer).await;
    assert_eq!(f.flag, MUX_NEW_MSG);
    assert_eq!(f.content.as_deref(), Some(b"still-works".as_ref()));
    stream.close();
    session.close();
}

/// 未知 id 的数据帧、对端 ConnClose 都必须被安全处理（不 panic，不误关会话）。
#[tokio::test]
async fn unknown_stream_frames_are_tolerated() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    inject(&mut peer, &msg(4242, b"orphan")).await;
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_CONN_CLOSE,
            id: 4242,
            content: None,
            window: None,
        },
    )
    .await;
    inject(
        &mut peer,
        &MuxFrame::send_ok(4242, INITIAL_WINDOW, 0, false),
    )
    .await;
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN_FAIL,
            id: 4242,
            content: None,
            window: None,
        },
    )
    .await;
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_PING_FLAG,
            id: MUX_PING_ID,
            content: None,
            window: None,
        },
    )
    .await;

    let mut saw_pong = false;
    for _ in 0..32 {
        if next_any_frame(&mut peer).await.flag == MUX_PING_RETURN {
            saw_pong = true;
            break;
        }
    }
    assert!(saw_pong, "会话应响应 ping");
    assert!(!session.is_closed());
    session.close();
}

/// 对端拒绝建流（NewConnFail）时 open_stream 必须立即返回错误并清理路由。
#[tokio::test]
async fn open_stream_handles_new_conn_fail() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    // 对端收到 NewConn 后回 Fail
    let peer_task = tokio::spawn(async move {
        let f = next_frame(&mut peer).await;
        assert_eq!(f.flag, MUX_NEW_CONN);
        peer.write_all(
            &MuxFrame {
                flag: MUX_NEW_CONN_FAIL,
                id: f.id,
                content: None,
                window: None,
            }
            .encode(),
        )
        .await
        .unwrap();
        // 保持连接直到测试结束
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(peer);
    });

    let result = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .expect("open_stream 未及时返回");
    assert!(
        matches!(result, Err(MuxError::ConnRefused(_))),
        "应返回 ConnRefused"
    );
    peer_task.await.unwrap();
    session.close();
}

/// close() 必须唤醒等待中的 open_stream 与 wait_closed，并让 recv 立即结束。
#[tokio::test]
async fn close_unblocks_pending_and_streams() {
    let (a, mut peer) = duplex(16 * 1024);
    let session = Arc::new(MuxSession::new(a));
    let s2 = Arc::clone(&session);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 8,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    // 一个挂起的 open_stream（对端不回应）
    let pending = tokio::spawn(async move { s2.open_stream().await });
    tokio::time::sleep(Duration::from_millis(30)).await;

    // 一个挂起的 recv_data
    let recv_task = tokio::spawn(async move { stream.recv_data().await });

    assert!(!session.is_closed());
    session.close();
    assert!(session.is_closed());

    let pending = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .expect("close 未唤醒 open_stream")
        .unwrap();
    assert!(matches!(pending, Err(MuxError::Closed)));

    let recv = tokio::time::timeout(Duration::from_secs(2), recv_task)
        .await
        .expect("close 未唤醒 recv_data")
        .unwrap();
    assert!(recv.is_none());

    tokio::time::timeout(Duration::from_secs(2), session.wait_closed())
        .await
        .expect("wait_closed 未在关闭后返回");
}

/// 底层连接断开（对端 EOF）必须传播为会话关闭 + 子流结束。
#[tokio::test]
async fn peer_eof_closes_session_and_streams() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 5,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    drop(peer); // 对端断开

    let recv = tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
        .await
        .expect("对端断开后 recv_data 未结束");
    assert!(recv.is_none());
    tokio::time::timeout(Duration::from_secs(5), session.wait_closed())
        .await
        .expect("对端断开后会话未关闭");
    assert!(session.is_closed());
    assert!(session.open_stream().await.is_err(), "关闭后不应再能建流");
}

/// 对端 `muxConnClose` 之后，已入队的数据必须先读完再 EOF
/// （对齐 Go `receiveWindow.Stop()`：不清空接收队列）。
#[tokio::test]
async fn peer_close_drains_buffered_data() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 11,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    // 三帧数据后紧跟关闭帧，全部一次性写入对端
    let mut buf = Vec::new();
    for part in [b"one".as_ref(), b"two".as_ref(), b"three".as_ref()] {
        buf.extend_from_slice(&msg(11, part).encode());
    }
    buf.extend_from_slice(
        &MuxFrame {
            flag: MUX_CONN_CLOSE,
            id: 11,
            content: None,
            window: None,
        }
        .encode(),
    );
    peer.write_all(&buf).await.unwrap();

    let mut got = Vec::new();
    while let Some(d) = tokio::time::timeout(Duration::from_secs(3), stream.recv_data())
        .await
        .expect("对端关闭后读取挂起")
    {
        got.extend_from_slice(&d);
    }
    assert_eq!(got, b"onetwothree", "对端关闭时丢弃了已入队数据");
    session.close();
}

/// 半关闭（只关发送方向）不能截断接收方向的数据。
#[tokio::test]
async fn send_half_close_keeps_receiving() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 6,
            content: None,
            window: None,
        },
    )
    .await;
    let stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    let (mut send, mut recv) = stream.into_split();
    send.close();
    drop(send);

    // 发送方向关闭后，对端继续下行数据仍必须可读
    inject(&mut peer, &msg(6, b"tail-response")).await;
    let got = tokio::time::timeout(Duration::from_secs(5), recv.recv_data())
        .await
        .expect("半关闭后接收方向被截断")
        .unwrap();
    assert_eq!(&got, b"tail-response");
    session.close();
}

// ===========================================================================
// 以下为对抗性加固回归测试（恶意/畸形对端）
// ===========================================================================

/// 只返回 1 字节就返回的 reader：模拟“一次 read 只给一部分”的极端碎片化到达，
/// 用来证明 `MuxFrame::decode` 会自行续读凑满整帧，既不会把半帧当完整帧，
/// 也不会把后续帧的字节误当成本帧内容。
struct DribbleReader {
    data: Vec<u8>,
    pos: usize,
}

impl AsyncRead for DribbleReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos >= self.data.len() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        buf.put_slice(&[b]);
        Poll::Ready(Ok(()))
    }
}

/// 每隔一次 poll 返回 `Interrupted`：`decode` 必须重试，而不是把信号中断
/// 当成协议错误、进而让整条会话断开。
struct InterruptingReader {
    data: Vec<u8>,
    pos: usize,
    interrupt_next: bool,
}

impl AsyncRead for InterruptingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos >= self.data.len() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.interrupt_next {
            self.interrupt_next = false;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "signal",
            )));
        }
        self.interrupt_next = true;
        let b = self.data[self.pos];
        self.pos += 1;
        buf.put_slice(&[b]);
        Poll::Ready(Ok(()))
    }
}

/// 逐字节到达时，数据帧与 sendOk 帧都必须被正确解析。
#[tokio::test]
async fn decode_handles_byte_by_byte_delivery() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&msg(7, b"fragmented").encode());
    bytes.extend_from_slice(&MuxFrame::send_ok(8, INITIAL_WINDOW, 17, true).encode());
    bytes.extend_from_slice(&MuxFrame::send_ok(9, 0, 0, false).encode());

    let mut r = DribbleReader {
        data: bytes,
        pos: 0,
    };
    let f1 = MuxFrame::decode(&mut r).await.unwrap().unwrap();
    assert_eq!((f1.flag, f1.id), (MUX_NEW_MSG, 7));
    assert_eq!(f1.content.as_deref(), Some(b"fragmented".as_ref()));

    let f2 = MuxFrame::decode(&mut r).await.unwrap().unwrap();
    assert_eq!((f2.flag, f2.id), (MUX_MSG_SEND_OK, 8));
    assert_eq!(
        MuxFrame::unpack_window(f2.window.unwrap()),
        (INITIAL_WINDOW, 17, true)
    );

    let f3 = MuxFrame::decode(&mut r).await.unwrap().unwrap();
    assert_eq!((f3.flag, f3.id), (MUX_MSG_SEND_OK, 9));
    // 帧边界处干净 EOF
    assert!(MuxFrame::decode(&mut r).await.unwrap().is_none());
}

/// 多帧粘连在同一段字节里：每次 decode 只消费一帧，不多吃也不少吃。
#[tokio::test]
async fn decode_splits_coalesced_frames() {
    let mut bytes = Vec::new();
    for i in 0..8i32 {
        bytes.extend_from_slice(&msg(i + 1, format!("frame-{i}").as_bytes()).encode());
    }
    bytes.extend_from_slice(
        &MuxFrame {
            flag: MUX_CONN_CLOSE,
            id: 9,
            content: None,
            window: None,
        }
        .encode(),
    );

    let mut cursor: &[u8] = &bytes;
    for i in 0..8i32 {
        let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
        assert_eq!((f.flag, f.id), (MUX_NEW_MSG, i + 1));
        assert_eq!(f.content.as_deref(), Some(format!("frame-{i}").as_bytes()));
    }
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!((f.flag, f.id), (MUX_CONN_CLOSE, 9));
    assert!(cursor.is_empty(), "所有字节应被恰好消费一次");
}

/// `Interrupted` 必须被当成可重试错误，而不是会话级致命错误。
#[tokio::test]
async fn decode_retries_on_interrupted() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&msg(1, b"ok").encode());
    let mut r = InterruptingReader {
        data: bytes,
        pos: 0,
        interrupt_next: false,
    };
    let f = MuxFrame::decode(&mut r).await.unwrap().unwrap();
    assert_eq!(f.content.as_deref(), Some(b"ok".as_ref()));
    assert!(MuxFrame::decode(&mut r).await.unwrap().is_none());
}

/// 长度字段超过 4085 时，`decode` 必须在**读取内容之前**就报错：
/// 否则一个 u16 长度就能制造一次 64KiB 的放大分配。
#[tokio::test]
async fn decode_rejects_oversize_length_before_consuming_body() {
    // 声明 65535 字节，但后面一个字节都不给
    let mut cursor: &[u8] = &[3, 1, 0, 0, 0, 0xff, 0xff];
    let err = MuxFrame::decode(&mut cursor).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "got {err:?}");
    // 未消费任何内容字节 -> 校验发生在分配/读取之前
    assert!(cursor.is_empty(), "越界长度不应继续消费 reader");
}

/// 编码器必须保证“长度字段 == 实际内容字节数”。
/// 内容超过 4085 时若用 `len as u16` 截断，会写出长度与实际不符的帧，
/// 令对端从这一帧开始永久失步。
#[test]
fn encode_never_emits_inconsistent_length_field() {
    let oversized = vec![0xAAu8; MAXIMUM_SEGMENT_SIZE + 100];
    let out = MuxFrame {
        flag: MUX_NEW_MSG,
        id: 4,
        content: Some(oversized),
        window: None,
    }
    .encode();
    assert_eq!(out.len(), 5 + 2 + MAXIMUM_SEGMENT_SIZE);
    let declared = u16::from_le_bytes([out[5], out[6]]) as usize;
    assert_eq!(declared, MAXIMUM_SEGMENT_SIZE, "长度字段必须与实际内容一致");

    for n in [0usize, 1, 2, 4085] {
        let out = MuxFrame {
            flag: MUX_NEW_MSG_PART,
            id: 1,
            content: Some(vec![7u8; n]),
            window: None,
        }
        .encode();
        assert_eq!(out.len(), 5 + 2 + n);
        assert_eq!(u16::from_le_bytes([out[5], out[6]]) as usize, n);
    }
}

/// 对端用非法/保留 id 建流：id <= 0 必须直接 `NewConnFail`，
/// 且**不得**留下任何路由条目（否则会挤占 MAX_STREAMS）。
#[tokio::test]
async fn new_conn_with_nonpositive_id_is_rejected_without_leaking_route() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    for id in [0i32, -1, -2_147_483_648] {
        inject(
            &mut peer,
            &MuxFrame {
                flag: MUX_NEW_CONN,
                id,
                content: None,
                window: None,
            },
        )
        .await;
        let f = next_frame(&mut peer).await;
        assert_eq!((f.flag, f.id), (MUX_NEW_CONN_FAIL, id));
    }

    assert_eq!(
        lock_route(&session.inner.streams).len(),
        0,
        "非法 id 不建流，路由表必须为空"
    );
    assert!(!session.is_closed());
    // 会话仍然可用
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 5,
            content: None,
            window: None,
        },
    )
    .await;
    let mut s = session.accept_stream().await.unwrap();
    assert_eq!(s.id(), 5);
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);
    s.close();
    session.close();
}

/// 对端对同一个 id 重复 `NewConn`：第二次必须 `NewConnFail`，
/// 不能覆盖已有路由（否则原 MuxStream 会变成孤儿）。
#[tokio::test]
async fn duplicate_new_conn_same_id_keeps_first_stream() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    let newc = |id| MuxFrame {
        flag: MUX_NEW_CONN,
        id,
        content: None,
        window: None,
    };

    inject(&mut peer, &newc(21)).await;
    let mut first = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    inject(&mut peer, &newc(21)).await;
    let dup = next_frame(&mut peer).await;
    assert_eq!((dup.flag, dup.id), (MUX_NEW_CONN_FAIL, 21));
    // 不应有第二条子流可被 accept
    let extra = tokio::time::timeout(Duration::from_millis(200), session.accept_stream()).await;
    assert!(extra.is_err(), "重复 id 不应产生第二条子流");

    // 原流仍然收到属于自己的数据
    inject(&mut peer, &msg(21, b"for-first")).await;
    let got = tokio::time::timeout(Duration::from_secs(3), first.recv_data())
        .await
        .expect("原流应仍可用")
        .unwrap();
    assert_eq!(&got, b"for-first");

    first.close();
    session.close();
}

/// 建流数达到 `MAX_STREAMS` 后必须拒绝，且关流后容量必须**真正释放**。
/// 覆盖 `close_stream_sync` / `Drop` 用 `try_lock` 时“抢不到锁就跳过清理”
/// 的缺陷：一旦残留，整个会话会永久无法再建流。
#[tokio::test]
async fn stream_capacity_is_released_after_close() {
    let (a, mut peer) = duplex(1024 * 1024);
    let session = Arc::new(MuxSession::new(a));

    let mut streams = Vec::new();
    for id in 1..=(MAX_STREAMS as i32) {
        inject(
            &mut peer,
            &MuxFrame {
                flag: MUX_NEW_CONN,
                id,
                content: None,
                window: None,
            },
        )
        .await;
        streams.push(session.accept_stream().await.unwrap());
    }
    for _ in 0..MAX_STREAMS {
        assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);
    }
    assert_eq!(lock_route(&session.inner.streams).len(), MAX_STREAMS);

    // 第 MAX_STREAMS+1 条必须被拒
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 9999,
            content: None,
            window: None,
        },
    )
    .await;
    let rej = next_frame(&mut peer).await;
    assert_eq!((rej.flag, rej.id), (MUX_NEW_CONN_FAIL, 9999));

    // 全部关掉后容量必须回收
    for mut s in streams {
        s.close();
    }
    let mut freed = false;
    for _ in 0..100 {
        if lock_route(&session.inner.streams).is_empty() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(freed, "关流后路由表未清空（存在永久残留）");

    // 现在必须能重新建流。
    // 注意：512 条 ConnClose 正在同一条出站 FIFO 里排队（与 Go 一致，
    // 关闭帧跟在数据后面），所以这里必须跳过它们，只认 NewConnOk。
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 4242,
            content: None,
            window: None,
        },
    )
    .await;
    let mut s = tokio::time::timeout(Duration::from_secs(5), session.accept_stream())
        .await
        .expect("容量未释放：无法再建流")
        .unwrap();
    assert_eq!(s.id(), 4242);
    let ok = next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await;
    assert_eq!(ok.id, 4242);
    s.close();
    session.close();
}

/// 指向已释放子流的**死弱引用**不得永久占用 `MAX_STREAMS` 名额。
#[tokio::test]
async fn dead_weak_routes_do_not_exhaust_stream_capacity() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    // 先在**不持锁**的情况下造出一批死弱引用（子流已 drop，强引用为 0）。
    // 注意不能在持路由表锁时 drop StreamState：它的 Drop 会再取同一把
    // 非重入锁来清理自己那条路由，同一线程上会自锁。
    let dead: Vec<(i32, Weak<StreamState>)> = (1..=(MAX_STREAMS as i32))
        .map(|id| {
            let state = Arc::new(StreamState::new(
                id,
                session.inner.write_tx.clone(),
                session.inner.ctrl_tx.clone(),
                session.inner.streams.clone(),
                session.inner.closed_tx.subscribe(),
            ));
            let weak = Arc::downgrade(&state);
            drop(state);
            (id, weak)
        })
        .collect();
    {
        let mut map = lock_route(&session.inner.streams);
        for (id, weak) in dead {
            map.insert(id, weak);
        }
    }
    assert_eq!(lock_route(&session.inner.streams).len(), MAX_STREAMS);

    // 对端建流必须成功：容量判定前要先剪掉死引用
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 777,
            content: None,
            window: None,
        },
    )
    .await;
    let mut s = tokio::time::timeout(Duration::from_secs(5), session.accept_stream())
        .await
        .expect("死弱引用把会话顶死在 MAX_STREAMS")
        .unwrap();
    assert_eq!(s.id(), 777);
    // 会话自己的出站 FIFO 里可能还有 ConnClose/ping，只等 NewConnOk
    assert_eq!(
        next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await.id,
        777
    );
    s.close();
    session.close();
}

/// 会话已关闭但子流仍被应用持有：`send_data` / `open_stream` 必须立即失败，
/// 不能因为关闭而与“慢对端”一起永久挂起。
#[tokio::test]
async fn closed_session_fails_fast_instead_of_hanging() {
    let (a, _peer) = duplex(1024);
    let session = Arc::new(MuxSession::new(a));

    let state = Arc::new(StreamState::new(
        1,
        session.inner.write_tx.clone(),
        session.inner.ctrl_tx.clone(),
        session.inner.streams.clone(),
        session.inner.closed_tx.subscribe(),
    ));
    let mut half = MuxSendHalf { id: 1, state };

    session.close();
    // 关闭后发送：要么报错，要么立刻返回；绝不能挂住
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        half.send_data(&vec![0u8; 4 * MAXIMUM_SEGMENT_SIZE]),
    )
    .await
    .expect("关闭后 send_data 挂起");
    assert!(r.is_err(), "关闭后 send_data 必须报错");

    let r = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .expect("关闭后 open_stream 挂起");
    assert!(r.is_err(), "关闭后 open_stream 必须返回错误");
}

/// 底层连接“能读但永远写不进去”：模拟对端完全不读 socket 造成的 TCP 反压。
struct DeadIo;

impl AsyncRead for DeadIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 读方向永远没有数据、也不 EOF
        Poll::Pending
    }
}

impl AsyncWrite for DeadIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending // 对端消费能力为 0
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// 控制队列被填满 + 写循环卡在 `write_all` 上：`close()` 必须让 `open_stream`
/// 立刻返回。
///
/// 这是最隐蔽的一条死锁链：
/// 写循环不可打断 → 永不退出 → `ctrl_rx` 永不 drop → `ctrl_tx.send` 永远等不到
/// 许可 → `open_stream` 挂在发送请求上，连 120s 超时都轮不到（超时只在
/// `select!` 的等待结果阶段生效）。写循环可取消后，`ctrl_rx` 随任务结束被丢弃，
/// `send` 立刻返回 `Err`。
#[tokio::test]
async fn close_unblocks_open_stream_when_ctrl_queue_is_full() {
    let session = Arc::new(MuxSession::new(DeadIo));

    // 先塞一帧，让写循环取走它并永久卡在 `write_all` 上（DeadIo 永不完成）
    session.inner.ctrl_tx.try_send(vec![0u8; 1]).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 写循环不再回来取 → 把剩余许可全部占满，且此后容量恒为 0
    let deadline = Instant::now() + Duration::from_secs(2);
    while session.inner.ctrl_tx.capacity() > 0 {
        let _ = session.inner.ctrl_tx.try_send(vec![0u8; 1]);
        assert!(Instant::now() < deadline, "无法填满 ctrl 队列");
    }
    assert_eq!(session.inner.ctrl_tx.capacity(), 0);

    let opener = tokio::spawn({
        let s = Arc::clone(&session);
        async move { s.open_stream().await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !opener.is_finished(),
        "ctrl 队列满时 open_stream 应阻塞在入队上"
    );

    session.close();
    let r = tokio::time::timeout(Duration::from_secs(5), opener)
        .await
        .expect("close 未能解开卡在满 ctrl 队列上的 open_stream（写循环不可取消）")
        .unwrap();
    assert!(r.is_err(), "关闭后 open_stream 必须返回错误");
}

/// 写队列（1024 帧）被填满时，`send_data` 卡在入队上必须能被 `close()` 唤醒。
///
/// 需要把发送窗口放大到能塞满 1024 帧，否则发送方会先卡在窗口上、
/// 走不到写队列这条路径。
#[tokio::test]
async fn close_unblocks_send_data_stuck_on_full_write_queue() {
    let session = Arc::new(MuxSession::new(DeadIo));

    let state = Arc::new(StreamState::new(
        1,
        session.inner.write_tx.clone(),
        session.inner.ctrl_tx.clone(),
        session.inner.streams.clone(),
        session.inner.closed_tx.subscribe(),
    ));
    lock_route(&session.inner.streams).insert(1, Arc::downgrade(&state));
    {
        // 对端宣称一个大窗口，使发送方不被窗口限制，直接灌满写队列
        let mut s = state.send.lock().await;
        s.max_size = MAX_WINDOW_SIZE;
    }
    let mut half = MuxSendHalf { id: 1, state };

    let writer = tokio::spawn(async move {
        let payload = vec![0x5Au8; (WRITE_QUEUE_FRAMES + 64) * MAXIMUM_SEGMENT_SIZE];
        half.send_data(&payload).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!writer.is_finished(), "写队列满时 send_data 应被背压住");

    session.close();
    let r = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("close 未能解开被写队列卡住的 send_data")
        .unwrap();
    assert!(r.is_err(), "关闭后 send_data 必须返回错误");
}

/// 控制队列被 ping 回包灌满时，读循环绝不能被卡死（只能用 try_send）。
#[tokio::test]
async fn reader_survives_ctrl_queue_pressure() {
    let (a, mut peer) = duplex(8 * 1024);
    let session = Arc::new(MuxSession::new(a));

    // 大量 ping：每个都产生一个 ctrl 回包；对端不读，ctrl 队列必然被填满
    let ping = MuxFrame {
        flag: MUX_PING_FLAG,
        id: MUX_PING_ID,
        content: Some(b"p".to_vec()),
        window: None,
    };
    for _ in 0..(CTRL_QUEUE_FRAMES * 2) {
        match tokio::time::timeout(Duration::from_millis(200), peer.write_all(&ping.encode())).await
        {
            Ok(Ok(())) => {}
            // duplex 缓冲被服务端的回包占满：说明写侧确实在反压，读侧仍须存活
            _ => break,
        }
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!session.is_closed(), "ctrl 队列满把会话读循环拖死了");
    session.close();
}

/// 数据帧**不得**解析出 `window` 字段，也不得多吃 8 字节。
///
/// `MUX_NEW_MSG` 在协议里没有窗口字段；若解码器错把它当 `sendOk` 处理，
/// 会把紧随其后的正常帧头吞掉，整条会话从此失步。
#[tokio::test]
async fn data_frame_does_not_consume_window_bytes() {
    let mut bytes = vec![MUX_NEW_MSG, 31, 0, 0, 0];
    bytes.extend_from_slice(&3u16.to_le_bytes());
    bytes.extend_from_slice(b"abc");
    // 紧随一条正常的 sendOk 帧
    bytes.extend_from_slice(&MuxFrame::send_ok(31, INITIAL_WINDOW, 0, false).encode());

    let mut cursor: &[u8] = &bytes;
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!((f.flag, f.id), (MUX_NEW_MSG, 31));
    assert_eq!(f.content.as_deref(), Some(b"abc".as_ref()));
    assert!(f.window.is_none(), "数据帧不应解析出 window 字段");

    // 下一帧必须正好是那条 sendOk，说明没有多读/少读字节
    let f = MuxFrame::decode(&mut cursor).await.unwrap().unwrap();
    assert_eq!(f.flag, MUX_MSG_SEND_OK);
    assert_eq!(
        MuxFrame::unpack_window(f.window.unwrap()).0,
        INITIAL_WINDOW
    );
    assert!(cursor.is_empty());
}

/// 未知 flag：会话必须干净断开（不 panic、不留任务）。
#[tokio::test]
async fn unknown_flag_closes_session_cleanly() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    peer.write_all(&[200u8, 1, 0, 0, 0]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), session.wait_closed())
        .await
        .expect("未知 flag 未关闭会话");
    assert!(session.is_closed());
    assert!(lock_route(&session.inner.streams).is_empty());
}

/// ping 内容为空时**不能**把空内容回显给 Go 对端：
/// Go `basePackager.Set` 对零长度内容报错并 `Close()` 整条 mux。
#[tokio::test]
async fn ping_with_empty_content_gets_non_empty_pong() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = MuxSession::new(a);

    // 零长度内容的 ping
    peer.write_all(&[MUX_PING_FLAG, 0xff, 0xff, 0xff, 0xff, 0, 0])
        .await
        .unwrap();

    let f = next_any_frame(&mut peer).await;
    assert_eq!(f.flag, MUX_PING_RETURN);
    assert_eq!(f.id, MUX_PING_ID);
    let content = f.content.expect("ping 回包必须有内容");
    assert!(
        !content.is_empty(),
        "空内容会让 Go 对端 pack 失败并关闭整条 mux"
    );
    assert!(content.ends_with(b"Z"), "应为 RFC3339 时间串");
    session.close();
}

/// 对端在发 `NewConn` 后直接 RST（不发 ConnClose）：会话关闭、路由表清空，
/// 已 accept 的子流读取立即结束 —— 计数不泄漏。
#[tokio::test]
async fn peer_reset_without_conn_close_cleans_routes() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 41,
            content: None,
            window: None,
        },
    )
    .await;
    let mut stream = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    drop(peer); // 直接 RST，无 ConnClose

    let r = tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
        .await
        .expect("对端 RST 后 recv_data 未结束");
    assert!(r.is_none());
    tokio::time::timeout(Duration::from_secs(5), session.wait_closed())
        .await
        .expect("对端 RST 后会话未关闭");
    assert!(
        lock_route(&session.inner.streams).is_empty(),
        "会话关闭后路由表必须清空"
    );
    assert!(lock_pending(&session.inner.pending).is_empty());
}

/// 反复建流/关流（本地 close 与对端 ConnClose 交替）：表必须回到空。
#[tokio::test]
async fn repeated_open_close_does_not_leak_routes() {
    let (a, mut peer) = duplex(1024 * 1024);
    let session = Arc::new(MuxSession::new(a));

    for round in 0..20i32 {
        let id = round + 1;
        inject(
            &mut peer,
            &MuxFrame {
                flag: MUX_NEW_CONN,
                id,
                content: None,
                window: None,
            },
        )
        .await;
        let mut s = session.accept_stream().await.unwrap();
        // 出站 FIFO 里还有上一轮的 sendOk/ConnClose，只认本轮的 NewConnOk
        assert_eq!(next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await.id, id);
        inject(&mut peer, &msg(id, b"x")).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), s.recv_data()).await;
        if round % 2 == 0 {
            s.close();
        } else {
            inject(
                &mut peer,
                &MuxFrame {
                    flag: MUX_CONN_CLOSE,
                    id,
                    content: None,
                    window: None,
                },
            )
            .await;
            drop(s);
        }
    }

    let mut empty = false;
    for _ in 0..100 {
        if lock_route(&session.inner.streams).is_empty() {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(empty, "反复建流/关流后路由表仍有残留");
    session.close();
}

/// 一条子流塞满 `RECV_BYTE_CAP` 后对端继续灌：超出部分必须被拒（关流），
/// 且会话 reader 仍存活 —— 内存不会无界增长。
#[tokio::test]
async fn receive_budget_cap_rejects_flood_without_stalling_reader() {
    let (a, mut peer) = duplex(256 * 1024);
    let session = Arc::new(MuxSession::new(a));

    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 51,
            content: None,
            window: None,
        },
    )
    .await;
    let mut slow = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    // 另一条正常消费的旁路子流：用来证明 reader 未死
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 52,
            content: None,
            window: None,
        },
    )
    .await;
    let mut fast = session.accept_stream().await.unwrap();
    assert_eq!(next_frame(&mut peer).await.flag, MUX_NEW_CONN_OK);

    let one = vec![0x11u8; MAXIMUM_SEGMENT_SIZE];
    let mut sent = 0usize;
    while sent < RECV_BYTE_CAP as usize + 64 * MAXIMUM_SEGMENT_SIZE {
        let bytes = msg_part(51, &one).encode();
        match tokio::time::timeout(Duration::from_millis(100), peer.write_all(&bytes)).await {
            Ok(Ok(())) => sent += MAXIMUM_SEGMENT_SIZE,
            _ => break,
        }
    }

    inject(&mut peer, &msg(52, b"alive")).await;
    let got = tokio::time::timeout(Duration::from_secs(5), fast.recv_data())
        .await
        .expect("reader 被灌爆的子流拖死")
        .unwrap();
    assert_eq!(&got, b"alive");

    let mut drained = 0usize;
    while let Some(d) = tokio::time::timeout(Duration::from_secs(5), slow.recv_data())
        .await
        .expect("超预算子流未关闭")
    {
        drained += d.len();
        assert!(drained <= RECV_BYTE_CAP as usize, "交付量超过字节预算");
    }

    fast.close();
    session.close();
}

/// 双方 id 空间重叠：对端先占住 id=1 时，我方 `open_stream` 必须自动避开，
/// 绝不能覆盖对端已有子流的同 id 路由（覆盖会让两条流的数据串台）。
#[tokio::test]
async fn open_stream_avoids_peer_occupied_id() {
    let (a, mut peer) = duplex(64 * 1024);
    let session = Arc::new(MuxSession::new(a));

    // 对端占住 id=1（我方 allocator 的第一个候选）
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 1,
            content: None,
            window: None,
        },
    )
    .await;
    let mut peer_stream = session.accept_stream().await.unwrap();
    assert_eq!(peer_stream.id(), 1);
    assert_eq!(
        next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await.id,
        1
    );

    let opener = tokio::spawn({
        let s = Arc::clone(&session);
        async move { s.open_stream().await }
    });
    // 我方发出的建流请求必须换一个 id
    let req = next_frame_matching(&mut peer, MUX_NEW_CONN).await;
    assert_ne!(req.id, 1, "不得复用对端已占用的 id");
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN_OK,
            id: req.id,
            content: None,
            window: None,
        },
    )
    .await;
    let mut mine = tokio::time::timeout(Duration::from_secs(5), opener)
        .await
        .expect("open_stream 未返回")
        .unwrap()
        .unwrap();
    assert_ne!(mine.id(), 1);

    // 两条流的数据不得串台
    inject(&mut peer, &msg(1, b"peer-data")).await;
    let got = tokio::time::timeout(Duration::from_secs(3), peer_stream.recv_data())
        .await
        .expect("对端子流未收到自己的数据")
        .unwrap();
    assert_eq!(&got, b"peer-data");

    mine.close();
    peer_stream.close();
    session.close();
}

/// `MAX_STREAMS` 个存活子流 + 一部分死弱引用混在一起时，容量判定只看存活项。
#[tokio::test]
async fn capacity_counts_only_live_streams() {
    let (a, mut peer) = duplex(1024 * 1024);
    let session = Arc::new(MuxSession::new(a));

    // 一半存活、一半死引用
    let half = MAX_STREAMS / 2;
    let dead: Vec<(i32, Weak<StreamState>)> = (1..=(half as i32))
        .map(|id| {
            let state = Arc::new(StreamState::new(
                10_000 + id,
                session.inner.write_tx.clone(),
                session.inner.ctrl_tx.clone(),
                session.inner.streams.clone(),
                session.inner.closed_tx.subscribe(),
            ));
            let weak = Arc::downgrade(&state);
            drop(state);
            (10_000 + id, weak)
        })
        .collect();
    {
        let mut map = lock_route(&session.inner.streams);
        for (id, weak) in dead {
            map.insert(id, weak);
        }
    }

    let mut live = Vec::new();
    for id in 1..=(half as i32) {
        inject(
            &mut peer,
            &MuxFrame {
                flag: MUX_NEW_CONN,
                id,
                content: None,
                window: None,
            },
        )
        .await;
        live.push(session.accept_stream().await.unwrap());
    }
    for _ in 0..half {
        // 构造死引用时每个 StreamState 的 Drop 都会往出站 FIFO 塞一个
        // ConnClose（对端会忽略未知 id），所以这里只认 NewConnOk。
        next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await;
    }

    // 存活数还没到上限，仍应允许新建（死引用不占名额）
    inject(
        &mut peer,
        &MuxFrame {
            flag: MUX_NEW_CONN,
            id: 5_000,
            content: None,
            window: None,
        },
    )
    .await;
    let mut extra = tokio::time::timeout(Duration::from_secs(5), session.accept_stream())
        .await
        .expect("死引用被计入容量，错误地拒绝了建流")
        .unwrap();
    assert_eq!(extra.id(), 5_000);
    assert_eq!(
        next_frame_matching(&mut peer, MUX_NEW_CONN_OK).await.id,
        5_000
    );

    extra.close();
    for mut s in live {
        s.close();
    }
    session.close();
}

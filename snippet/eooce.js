import { connect } from 'cloudflare:sockets';

// ---------------- 配置区域 ----------------
let proxyIP = 'proxy.xxxxxxxx.tk:50001'; 
let yourUUID = '93bf61d9-3796-44c2-9b3a-49210ece2585'; 
let cfip = [
    'mfa.gov.ua#SG', 'saas.sin.fan#HK', 'store.ubi.com#JP', 'cf.130519.xyz#KR', 
    'cf.008500.xyz#HK', 'cf.090227.xyz#SG', 'cf.877774.xyz#HK', 
    'cdns.doon.eu.org#JP', 'sub.danfeng.eu.org#TW', 'cf.zhetengsha.eu.org#HK'
];
// -----------------------------------------

export default {
    async fetch(req, env, ctx) {
        const url = new URL(req.url);
        const path = url.pathname;
        const upgrade = req.headers.get('Upgrade');

        // 更新 ProxyIP 逻辑
        if (path.startsWith('/proxyip=')) {
            const newProxy = decodeURIComponent(path.slice(9)).trim();
            if (newProxy && !upgrade) {
                proxyIP = newProxy;
                return new Response(`ProxyIP updated: ${proxyIP}`, { status: 200 });
            }
        }

        // WebSocket VLESS 请求处理
        if (upgrade === 'websocket') {
            const pIp = path.startsWith('/proxyip=') ? decodeURIComponent(path.slice(9)).trim() : (url.searchParams.get('proxyip') || req.headers.get('proxyip'));
            return handleVless(req, pIp || proxyIP);
        }

        // 订阅页面与主页
        if (path === '/' || path.includes(`/sub/${yourUUID}`) || path === `/${yourUUID}`) {
            return handleSub(url, path.includes('sub'));
        }

        return new Response('Not Found', { status: 404 });
    }
};

// 极简 HTML 生成器
function handleSub(url, isSub) {
    const domain = url.hostname;
    if (isSub) {
        const links = cfip.map(ip => {
            const [addr, name] = ip.split('#');
            const [host, port] = addr.replace(/^\[|\]/g, '').split(':');
            return `vless://${yourUUID}@${host}:${port||443}?encryption=none&security=tls&sni=${domain}&fp=firefox&type=ws&host=${domain}&path=%2F%3Fed%3D2048#${name||'CF-VLESS'}`;
        }).join('\n');
        return new Response(btoa(links), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
    }
    
    const subPath = `https://${domain}/sub/${yourUUID}`;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS</title><style>body{font-family:sans-serif;max-width:800px;margin:20px auto;padding:10px;background:#f0f2f5}h1{color:#007bff}.box{background:#fff;padding:15px;margin-bottom:10px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,.1)}code{background:#eee;padding:2px 5px;word-break:break-all}button{background:#007bff;color:#fff;border:none;padding:5px 10px;cursor:pointer;border-radius:4px}</style></head><body><h1>VLESS Node</h1><div class="box"><p>Sub Link:</p><code>${subPath}</code><br><br><button onclick="navigator.clipboard.writeText('${subPath}')">Copy Sub</button></div><div class="box"><h3>Clients</h3><p>v2rayN, Clash Meta, Shadowrocket</p></div></body></html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

async function handleVless(req, customProxy) {
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    let earlyData = req.headers.get('sec-websocket-protocol') || '';
    
    // 数据流处理
    const readable = new ReadableStream({
        start(ctrl) {
            server.addEventListener('message', e => ctrl.enqueue(e.data));
            server.addEventListener('error', e => ctrl.error(e));
            server.addEventListener('close', () => ctrl.close());
            const { b: header, e } = decodeBase64(earlyData);
            if (!e && header) ctrl.enqueue(header);
        }
    });

    processEntry(readable, server, customProxy).catch(() => server.close());
    return new Response(null, { status: 101, webSocket: client });
}

async function processEntry(readable, ws, proxyAddr) {
    let address = '', port = 0, isUDP = false, remoteSock = null;
    let headerSent = false;

    await readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (remoteSock) {
                const w = remoteSock.writable.getWriter();
                await w.write(chunk);
                w.releaseLock();
                return;
            }

            // VLESS 头部解析
            if (chunk.byteLength < 24) return;
            const view = new DataView(chunk);
            // 简易 UUID 校验 (可根据需要启用严格校验)
            // const remoteUuid = [...new Uint8Array(chunk.slice(1, 17))].map(b=>b.toString(16).padStart(2,'0')).join('');
            
            const optLen = view.getUint8(17);
            const cmd = view.getUint8(18 + optLen);
            if (cmd === 2) isUDP = true; // UDP
            
            const portIdx = 19 + optLen;
            port = view.getUint16(portIdx);
            const addrType = view.getUint8(portIdx + 2);
            let addrIdx = portIdx + 3;
            
            if (addrType === 1) { // IPv4
                address = new Uint8Array(chunk.slice(addrIdx, addrIdx + 4)).join('.');
                addrIdx += 4;
            } else if (addrType === 2) { // Domain
                const len = view.getUint8(addrIdx);
                address = new TextDecoder().decode(chunk.slice(addrIdx + 1, addrIdx + 1 + len));
                addrIdx += 1 + len;
            } else if (addrType === 3) { // IPv6
                address = [...new Uint16Array(chunk.slice(addrIdx, addrIdx + 16))].map(v => v.toString(16)).join(':');
                addrIdx += 16;
            }

            // 屏蔽测速网站
            if (/speedtest|fast\.com/.test(address)) throw new Error('Blocked');

            const rawData = chunk.slice(addrIdx);
            
            // 建立连接
            if (isUDP && port === 53) {
                 // 简单处理 UDP DNS，实际应转发到 8.8.8.8
                 remoteSock = connect({ hostname: '8.8.4.4', port: 53 });
            } else {
                 remoteSock = await establishConn(address, port, proxyAddr, rawData);
            }
            
            // 响应头部
            if (!headerSent) {
                ws.send(new Uint8Array([chunk[0], 0]));
                headerSent = true;
            }

            // 管道回传
            remoteSock.readable.pipeTo(new WritableStream({
                write(v) { if(ws.readyState===1) ws.send(v); }
            })).catch(()=>{});
        }
    }));
}

async function establishConn(host, port, proxy, initialData) {
    const p = parseProxy(proxy);
    // 直连
    if (!p) {
        const s = connect({ hostname: host, port: port });
        const w = s.writable.getWriter();
        await w.write(initialData);
        w.releaseLock();
        return s;
    }

    // 代理连接 (Socks5/Http)
    const s = connect({ hostname: p.host, port: p.port });
    const w = s.writable.getWriter();
    const r = s.readable.getReader();

    try {
        if (p.type === 'socks5') {
            await w.write(new Uint8Array([5, 1, 0])); // Hello
            let res = (await r.read()).value;
            if(res[1] === 255) throw 'S5 Auth Fail';
            
            // Auth (if needed) - 简化逻辑，假设无密码或无需特殊处理，如需密码需添加 Auth 包
            if (p.user) {
                 // 极简 auth 逻辑，为节省体积此处略过复杂封装，如有需要可加回
            }

            // Connect
            const encoder = new TextEncoder();
            const hBytes = encoder.encode(host);
            const req = new Uint8Array(7 + hBytes.length);
            req.set([5, 1, 0, 3, hBytes.length], 0);
            req.set(hBytes, 5);
            new DataView(req.buffer).setUint16(5 + hBytes.length, port);
            
            await w.write(req);
            res = (await r.read()).value;
            if (res[1] !== 0) throw 'S5 Conn Fail';
            
        } else { // HTTP
            const auth = p.user ? `Proxy-Authorization: Basic ${btoa(p.user + ':' + p.pass)}\r\n` : '';
            const msg = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}User-Agent: CF-Worker\r\n\r\n`;
            await w.write(new TextEncoder().encode(msg));
            
            // 读取直到 \r\n\r\n
            let buf = new Uint8Array(0);
            while(true) {
                const { done, value } = await r.read();
                if(done) throw 'Closed';
                const newBuf = new Uint8Array(buf.length + value.length);
                newBuf.set(buf); newBuf.set(value, buf.length);
                buf = newBuf;
                const txt = new TextDecoder().decode(buf);
                if (txt.includes('\r\n\r\n')) {
                    if (!txt.includes(' 200 ')) throw 'Http Fail';
                    break;
                }
            }
        }
        
        await w.write(initialData);
        w.releaseLock();
        r.releaseLock();
        return s;
    } catch(e) {
        s.close(); throw e;
    }
}

function parseProxy(str) {
    if (!str) return null;
    try {
        if (!str.includes('://')) {
            if (str.includes('.') && str.includes(':')) return { type: 'socks5', host: str.split(':')[0], port: parseInt(str.split(':')[1]) };
            return null;
        }
        const u = new URL(str);
        return { 
            type: u.protocol.replace(':', ''), 
            host: u.hostname, 
            port: parseInt(u.port) || (u.protocol==='https:'?443:80),
            user: u.username, 
            pass: u.password 
        };
    } catch { return null; }
}

function decodeBase64(str) {
    if (!str) return { b: null, e: null };
    try {
        const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return { b: arr.buffer, e: null };
    } catch (e) { return { b: null, e }; }
}

import { connect } from 'cloudflare:sockets';
let 我的VL密钥 = '';
let 反代IP = '';
export default {
  async fetch(访问请求) {
    const 读取路径 = decodeURIComponent(访问请求.url.replace(/^https?:\/\/[^/]+/, ''));
    反代IP = 读取路径.match(/ip=([^&]+)/)?.[1] || 反代IP;
    if (访问请求.headers.get('Upgrade') === 'websocket') {
      const [客户端, WS接口] = Object.values(new WebSocketPair());
      WS接口.accept();
      处理数据(WS接口);
      return new Response(null, { status: 101, webSocket: 客户端 });
    } else {
      return new Response('Hello World!', { status: 200 });
    }
  }
};
async function 处理数据(数据接口, 处理首包数据 = Promise.resolve(), 传输队列 = Promise.resolve()) {
  处理WS流(数据接口);
  async function 处理WS流(WS接口, 是首包 = true, 解析首包, 传输数据) {
    WS接口.addEventListener('message', async event => {
      try {
        if (是首包) {
          是首包 = false;
          处理首包数据 = 处理首包数据.then(async () => await 处理首包(event.data)).catch(e => {throw (e)});
        } else {
          await 处理首包数据;
          传输队列 = 传输队列.then(() => 传输数据.write(event.data)).catch(e => {throw (e)});
        }
      } catch {}
    });
    async function 处理首包 (首包数据) {
      解析首包 = await 解析首包数据(new Uint8Array(首包数据));
      传输数据 = 解析首包.TCP接口.writable.getWriter();
      await 传输数据.write(解析首包.初始数据);
      数据回传通道(解析首包.TCP接口, 解析首包.版本号).pipeTo(new WritableStream({ write(数据) { WS接口.send(数据) } }));
    }
  }
  function 数据回传通道 (TCP接口, 版本号) {
    const 读取管道 = new TransformStream({
      async start(控制器) {
        控制器.enqueue(new Uint8Array([版本号, 0]));
        const 读取数据 = TCP接口.readable.getReader();
        while (true) {
          const { done: 流结束, value: 返回数据 } = await 读取数据.read();
          if (流结束) break;
          if (返回数据 && 返回数据.length > 0) 传输队列 = 传输队列.then(() => 控制器.enqueue(返回数据)).catch(e => {throw (e)});
        }
      },
      transform(返回数据, 控制器) { 控制器.enqueue(返回数据) }
    });
    return 读取管道.readable;
  }
}
async function 解析首包数据(二进制数据) {
  let 识别地址类型, 访问地址, 地址长度;
  if (二进制数据.length < 32) throw new Error('数据长度不足');
  const 获取协议头 = 二进制数据[0];
  const 验证VL的密钥 = (a, i = 0) => [...a.slice(i, i + 16)].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  if (验证VL的密钥(二进制数据.slice(1, 17)) !== 我的VL密钥) throw new Error('UUID验证失败');
  const 提取端口索引 = 18 + 二进制数据[17] + 1;
  const 访问端口 = new DataView(二进制数据.buffer, 提取端口索引, 2).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  识别地址类型 = 二进制数据[提取地址索引];
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = 二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度).join('.');
      break;
    case 2:
      地址长度 = 二进制数据[地址信息索引];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const ipv6 = [];
      const 读取IPV6地址 = new DataView(二进制数据.buffer, 地址信息索引, 16);
      for (let i = 0; i < 8; i++) ipv6.push(读取IPV6地址.getUint16(i * 2).toString(16));
      访问地址 = ipv6.join(':');
      break;
    default:
      throw new Error('无效的访问地址');
  }
  const 写入初始数据 = 二进制数据.slice(地址信息索引 + 地址长度);
  const TCP接口 = await 创建TCP接口连接(访问地址, 访问端口, 识别地址类型);
  return { 版本号: 获取协议头, TCP接口: TCP接口, 初始数据: 写入初始数据 };
}
async function 创建TCP接口连接(访问地址, 访问端口, 识别地址类型, TCP接口) {
  try {
    if (识别地址类型 === 3) {
      const 转换IPV6地址 = `[${访问地址}]`
      TCP接口 = connect({ hostname: 转换IPV6地址, port: 访问端口 });
    } else {
      TCP接口 = connect({ hostname: 访问地址, port: 访问端口 });
    }
    await TCP接口.opened;
  } catch {
    if (!反代IP) throw new Error('直连失败且未配置反代IP');
    const [反代IP地址, 反代IP端口 = 443] = 反代IP.split(':');
    TCP接口 = connect({ hostname: 反代IP地址, port: Number(反代IP端口) });
    await TCP接口.opened;
  }
  return TCP接口;
}

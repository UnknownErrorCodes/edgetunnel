
import { connect } from 'cloudflare:sockets';

let userID = '';
let prxyIP = '';
let sub = '';
let subConverter = atob('U1VCQVBJLmZ4eGsuZGVkeW4uaW8=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let sPtl = 'https';
let subEmoji = 'true';
let sos5dess = '';
let pS5A = {}; 
let eSs = false;
let spasswd = '1QAZ';
let feUD ;
let fHN ;
let noTLS = 'false'; 
const expire = 4102329600;
let prxyIs;
let s0ks5s;
let gScks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];
let adreses = [];
let adresespi = [];
let adnots = [];
let antai = [];
let adrescv = [];
let DLS = 8;
let rmrkIdx = 1;
let FileName = atob('ZWRnZXR1bm5lbA==');
let BoTken;
let CatD; 
let pryhsts = [];
let proyhstsUL = '';
let RproxyIP = 'false';
let htpPts = ["2053","2083","2087","2096","8443"];
let 有Y效X时S间J = 7;
let 更G新X时S间J = 3;
let usIDLw;
let uerDTie = "";
let poyIPPol = [];
let path = atob('Lz9lZD0yNTYw');
let 动态优优艾迪;
let 林克 = [];
let baHsts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
export default {
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
			if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
				动态优优艾迪 = env.KEY || env.TOKEN || userID;
				有Y效X时S间J = Number(env.TIME) || 有Y效X时S间J;
				更G新X时S间J = Number(env.UPTIME) || 更G新X时S间J;
				const usrIs = await 生成动态优优艾迪(动态优优艾迪);
				userID = usrIs[0];
				usIDLw = usrIs[1];
			}

			if (!userID) {
				return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', { 
					status: 404,
					headers: {
						"Content-Type": "text/plain;charset=utf-8",
					}
				});
			}
			const curntDat = new Date();
			curntDat.setHours(0, 0, 0, 0); 
			const timestamp = Math.ceil(curntDat.getTime() / 1000);
			const fUIM5 = await 双重哈希(`${userID}${timestamp}`);
			feUD = [
				fUIM5.slice(0, 8),
				fUIM5.slice(8, 12),
				fUIM5.slice(12, 16),
				fUIM5.slice(16, 20),
				fUIM5.slice(20)
			].join('-');
			
			fHN = `${fUIM5.slice(6, 9)}.${fUIM5.slice(13, 19)}`;

			prxyIP = env.PROXYIP || env.proxyip || prxyIP;
			prxyIs = await 整理(prxyIP);
			prxyIP = prxyIs[Math.floor(Math.random() * prxyIs.length)];

			sos5dess = env.SOCKS5 || sos5dess;
			s0ks5s = await 整理(sos5dess);
			sos5dess = s0ks5s[Math.floor(Math.random() * s0ks5s.length)];
			sos5dess = sos5dess.split('//')[1] || sos5dess;
			if (env.GO2SOCKS5) gScks5s = await 整理(env.GO2SOCKS5);
			if (env.CFPORTS) htpPts = await 整理(env.CFPORTS);
			if (env.BAN) baHsts = await 整理(env.BAN);
			if (sos5dess) {
				try {
					pS5A = sck5AdessPser(sos5dess);
					RproxyIP = env.RPROXYIP || 'false';
					eSs = true;
				} catch (err) {
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !prxyIP ? 'true' : 'false';
					eSs = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !prxyIP ? 'true' : 'false';
			}

			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				if (env.ADD) adreses = await 整理(env.ADD);
				if (env.ADDAPI) adresespi = await 整理(env.ADDAPI);
				if (env.ADDNOTLS) adnots = await 整理(env.ADDNOTLS);
				if (env.ADDNOTLSAPI) antai = await 整理(env.ADDNOTLSAPI);
				if (env.ADDCSV) adrescv = await 整理(env.ADDCSV);
				DLS = Number(env.DLS) || DLS;
				rmrkIdx = Number(env.CSVREMARK) || rmrkIdx;
				BoTken = env.TGTOKEN || BoTken;
				CatD = env.TGID || CatD; 
				FileName = env.SUBNAME || FileName;
				subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
				if (subEmoji == '0') subEmoji = 'false';
				if (env.LINK) 林克 = await 整理(env.LINK) ;
				sub = env.SUB || sub;
				subConverter = env.SUBAPI || subConverter;
				if (subConverter.includes("http://") ){
					subConverter = subConverter.split("//")[1];
					sPtl = 'http';
				} else {
					subConverter = subConverter.split("//")[1] || subConverter;
				}
				subConfig = env.SUBCONFIG || subConfig;
				if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
				if (url.searchParams.has('notls')) noTLS = 'true';

				if (url.searchParams.has('proxyip')) {
					path = `/?ed=2560&proxyip=${url.searchParams.get('proxyip')}`;
					RproxyIP = 'false';
				} else if (url.searchParams.has('socks5')) {
					path = `/?ed=2560&socks5=${url.searchParams.get('socks5')}`;
					RproxyIP = 'false';
				} else if (url.searchParams.has('socks')) {
					path = `/?ed=2560&socks5=${url.searchParams.get('socks')}`;
					RproxyIP = 'false';
				}

				const 路L径J = url.pathname.toLowerCase();
				if (路L径J == '/') {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				} else if (路L径J == `/${feUD}`) {
					const fakeConfig = await 生S成C配P置Z信X息X(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				} else if (url.pathname == `/${动态优优艾迪}/edit` || 路L径J == `/${userID}/edit`) {
					const html = await KV(request, env);
					return html;
				} else if (url.pathname == `/${动态优优艾迪}` || 路L径J == `/${userID}`) {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					const 维列斯Config = await 生S成C配P置Z信X息X(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, env);
					const now = Date.now();
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;

					if (userAgent && userAgent.includes('mozilla')){
						return new Response(`<div style="font-size:13px;">${维列斯Config}</div>`, {
							status: 200,
							headers: {
								"Content-Type": "text/html;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
								"Cache-Control": "no-store",
							}
						});
					} else {
						return new Response(`${维列斯Config}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				} else {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
				}
			} else {
				sos5dess = url.searchParams.get('socks5') || sos5dess;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) sos5dess = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					sos5dess = url.pathname.split('://')[1].split('#')[0];
					if (sos5dess.includes('@')){
						let userDPaWssFAword = sos5dess.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userDPaWssFAword) && !userDPaWssFAword.includes(':')) userDPaWssFAword = atob(userDPaWssFAword);
						sos5dess = `${userDPaWssFAword}@${sos5dess.split('@')[1]}`;
					}
				}

				if (sos5dess) {
					try {
						pS5A = sck5AdessPser(sos5dess);
						eSs = true;
					} catch (err) {
						let e = err;
						console.log(e.toString());
						eSs = false;
					}
				} else {
					eSs = false;
				}

				if (url.searchParams.has('proxyip')){
					prxyIP = url.searchParams.get('proxyip');
					eSs = false;
				} else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
					prxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
					eSs = false;
				} else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
					prxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
					eSs = false;
				} else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
					prxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
					eSs = false;
				}

				return await 维列斯偶WS汉德(request);
			}
		} catch (err) {
			let e = err;
			return new Response(e.toString());
		}
	},
};

async function 维列斯偶WS汉德(request) {

	const wbScketPa = new WebSocketPair();
	const [client, webSocket] = Object.values(wbScketPa);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);


	let remoteSocketWapper = {
		value: null,
	};

	let isDns = false;

	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				adrssTye,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				维列斯Version = new Uint8Array([0, 0]),
				isUDP,
			} = press维斯Heer(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) {
				throw new Error(message);
				return;
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
					return;
				}
			}
			const 维斯Resneader = new Uint8Array([维列斯Version[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, 维斯Resneader, log);
			}
			if (!baHsts.includes(addressRemote)) {
				log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
				hanCPOuADtBod(remoteSocketWapper, adrssTye, addressRemote, portRemote, rawClientData, webSocket, 维斯Resneader, log);
			} else {
				throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
			}
		},
		close() {
			log(`readableWebSocketStream 已关闭`);
		},
		abort(reason) {
			log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream 管道错误', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

async function hanCPOuADtBod(remoteSocket, adrssTye, addressRemote, portRemote, rawClientData, webSocket, 维斯Resneader, log,) {
	async function useSocks5Pattern(address) {
		if ( gScks5s.includes(atob('YWxsIGlu')) || gScks5s.includes(atob('Kg==')) ) return true;
		return gScks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}

	async function connectAndWrite(address, port, socks = false) {
		log(`connected to ${address}:${port}`);
		const tS0cssset = socks ? await skss5Cect(adrssTye, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tS0cssset;
		const writer = tS0cssset.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tS0cssset;
	}


	async function retry() {
		if (eSs) {

			tS0cssset = await connectAndWrite(addressRemote, portRemote, true);
		} else {

			if (!prxyIP || prxyIP == '') {
				prxyIP = atob(`UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==`);
			} else if (prxyIP.includes(']:')) {
				portRemote = prxyIP.split(']:')[1] || portRemote;
				prxyIP = prxyIP.split(']:')[0] || prxyIP;
			} else if (prxyIP.split(':').length === 2) {
				portRemote = prxyIP.split(':')[1] || portRemote;
				prxyIP = prxyIP.split(':')[0] || prxyIP;
			}
			if (prxyIP.includes('.tp')) portRemote = prxyIP.split('.tp')[1].split('.')[0] || portRemote;
			tS0cssset = await connectAndWrite(prxyIP || addressRemote, portRemote);
		}
		tS0cssset.closed.catch(error => {
			console.log('retry tS0cssset closed error', error);
		}).finally(() => {
			safClseWbSckt(webSocket);
		})

		reoteSketT0WS(tS0cssset, webSocket, 维斯Resneader, null, log);
	}

	let useSocks = false;
	if (gScks5s.length > 0 && eSs ) useSocks = await useSocks5Pattern(addressRemote);

	let tS0cssset = await connectAndWrite(addressRemote, portRemote, useSocks);

	reoteSketT0WS(tS0cssset, webSocket, 维斯Resneader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;

	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});


			webSocketServer.addEventListener('close', () => {
				safClseWbSckt(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('WebSocket 服务器发生错误');
				controller.error(err);
			});

			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {

		},


		cancel(reason) {

			if (readableStreamCancel) {
				return;
			}
			log(`可读流被取消，原因是 ${reason}`);
			readableStreamCancel = true;
			safClseWbSckt(webSocketServer);
		}
	});

	return stream;
}




function press维斯Heer(维列斯爸父, userID) {
	if (维列斯爸父.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(维列斯爸父.slice(0, 1));

	let isValidUser = false;
	let isUDP = false;

	function isUserIDValid(userID, usIDLw, buffer) {
		const uerIDAra = new Uint8Array(buffer.slice(1, 17));
		const uerISting = stringify(uerIDAra);
		return uerISting === userID || uerISting === usIDLw;
	}


	isValidUser = isUserIDValid(userID, usIDLw, 维列斯爸父);

	if (!isValidUser) {
		return {
			hasError: true,
			message: `invalid user ${(new Uint8Array(维列斯爸父.slice(1, 17)))}`,
		};
	}


	const optLength = new Uint8Array(维列斯爸父.slice(17, 18))[0];

	const command = new Uint8Array(
		维列斯爸父.slice(18 + optLength, 18 + optLength + 1)
	)[0];


	if (command === 1) {

	} else if (command === 2) {

		isUDP = true;
	} else {

		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}


	const ptIdx = 18 + optLength + 1;
	const portBuffer = 维列斯爸父.slice(ptIdx, ptIdx + 2);

	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = ptIdx + 2;
	const addressBuffer = new Uint8Array(
		维列斯爸父.slice(addressIndex, addressIndex + 1)
	);

	const adrssTye = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';

	switch (adrssTye) {
		case 1:

			addressLength = 4;

			addressValue = new Uint8Array(
				维列斯爸父.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:

			addressLength = new Uint8Array(
				维列斯爸父.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;

			addressValue = new TextDecoder().decode(
				维列斯爸父.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				维列斯爸父.slice(addressValueIndex, addressValueIndex + addressLength)
			);

			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
				message: `invild adrssTye is ${adrssTye}`,
			};
	}

	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, adrssTye is ${adrssTye}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue, 
		adrssTye,				
		portRemote,				 
		rawDataIndex: addressValueIndex + addressLength,  
		维列斯Version: version,	  
		isUDP,					
	};
}

async function reoteSketT0WS(remoteSocket, webSocket, 维斯Resneader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let 维列斯Header = 维斯Resneader;
	let hasIncomingData = false; 

	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				async write(chunk, controller) {
					hasIncomingData = true; 
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}

					if (维列斯Header) {
						webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
						维列斯Header = null; 
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`reoteSketT0WS has exception `,
				error.stack || error
			);
			safClseWbSckt(webSocket);
		});

	if (hasIncomingData === false && retry) {
		log(`retry`);
		retry(); 
	}
}


function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: undefined, error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		
		const decode = atob(base64Str);
		
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: undefined, error };
	}
}


function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}


const WS_READY_STATE_OPEN = 1;	
const WS_READY_STATE_CLOSING = 2;  

function safClseWbSckt(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safClseWbSckt error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}


function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
		byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
		byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
		byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
		byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}


function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError(`生成的 UUID 不符合规范 ${uuid}`); 
	}
	return uuid;
}


async function handleDNSQuery(udpChunk, webSocket, 维斯Resneader, log) {
	try {

		const dnsServer = '8.8.4.4'; 
		const dnsPort = 53; 

		let 维列斯Header = 维斯Resneader; 

		const tS0cssset = connect({
			hostname: dnsServer,
			port: dnsPort,
		});

		log(`连接到 ${dnsServer}:${dnsPort}`); 
		const writer = tS0cssset.writable.getWriter();
		await writer.write(udpChunk); 
		writer.releaseLock(); 

		await tS0cssset.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					if (维列斯Header) {
						webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
						维列斯Header = null; 
					} else {
						webSocket.send(chunk);
					}
				}
			},
			close() {
				log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); 
			},
			abort(reason) {
				console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); 
			},
		}));
	} catch (error) {
		console.error(
			`handleDNSQuery 函数发生异常，错误信息: ${error.message}`
		);
	}
}


async function skss5Cect(adrssTye, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = pS5A;
	const socket = connect({
		hostname, 
		port,	
	});

	const socksGreeting = new Uint8Array([5, 2, 0, 2]);

	const writer = socket.writable.getWriter();

	await writer.write(socksGreeting);
	log('已发送 SOCKS5 问候消息');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	if (res[0] !== 0x05) {
		log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
		return;
	}
	if (res[1] === 0xff) {
		log("服务器不接受任何认证方法");
		return;
	}

	if (res[1] === 0x02) {
		log("SOCKS5 服务器需要认证");
		if (!username || !password) {
			log("请提供用户名和密码");
			return;
		}
		const authRequest = new Uint8Array([
			1,				   
			username.length,	
			...encoder.encode(username), 
			password.length,	
			...encoder.encode(password)  
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log("SOCKS5 服务器认证失败");
			return;
		}
	}

	let DSTADDR;	
	switch (adrssTye) {
		case 1: 
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 2: 
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 3: 
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`无效的地址类型: ${adrssTye}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);

	await writer.write(socksRequest);
	log('已发送 SOCKS5 请求');

	res = (await reader.read()).value;

	if (res[1] === 0x00) {
		log("SOCKS5 连接已建立");
	} else {
		log("SOCKS5 连接建立失败");
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}


function sck5AdessPser(address) {

	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;


	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
		}
		[username, password] = formers;
	}
	const latters = latter.split(":");
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	}
	hostname = latters.join(":");
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	}
	return {
		username,  
		password,  
		hostname, 
		port,	
	}
}


function 恢H复F伪W装Z信X息X(content, userID, hostName, isBase64) {
	if (isBase64) content = atob(content); 
	
值
	content = content.replace(new RegExp(feUD, 'g'), userID)
				   .replace(new RegExp(fHN, 'g'), hostName);
	
	if (isBase64) content = btoa(content);  
	
	return content;
}


async function 双重哈希(文本) {
	const 编码器 = new TextEncoder();

	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
	const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
	const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
  
	return 第二次十六进制.toLowerCase();
}

async function 代理URL(代D理L网W址Z, 目M标B网W址Z) {
	const 网W址Z列L表B = await 整理(代D理L网W址Z);
	const 完W整Z网W址Z = 网W址Z列L表B[Math.floor(Math.random() * 网W址Z列L表B.length)];

	let 解J析X后H的D网W址Z = new URL(完W整Z网W址Z);
	console.log(解J析X后H的D网W址Z);
	let 协议 = 解J析X后H的D网W址Z.protocol.slice(0, -1) || 'https';
	let 主Z机J名M = 解J析X后H的D网W址Z.hostname;
	let 路L径J名M = 解J析X后H的D网W址Z.pathname;
	let 查C询X参C数S = 解J析X后H的D网W址Z.search;

	if (路L径J名M.charAt(路L径J名M.length - 1) == '/') {
		路L径J名M = 路L径J名M.slice(0, -1);
	}
	路L径J名M += 目M标B网W址Z.pathname;

	let 新X网W址Z = `${协议}://${主Z机J名M}${路L径J名M}${查C询X参C数S}`;

	let 响X应Y = await fetch(新X网W址Z);

	let 新X响X应Y = new Response(响X应Y.body, {
		status: 响X应Y.status,
		statusText: 响X应Y.statusText,
		headers: 响X应Y.headers
	});

	新X响X应Y.headers.set('X-New-URL', 新X网W址Z);

	return 新X响X应Y;
}

const 啥S啥S啥_写X的D这Z是S啥S啊A = atob('ZG14bGMzTT0=');
function 配p置z信x息x(UUID, 域Y名M地D址Z) {
	const 协X议Y类L型X = atob(啥S啥S啥_写X的D这Z是S啥S啊A);
	
	const 别名 = FileName;
	let 地D址Z = 域Y名M地D址Z;
	let 端D口K = 443;

	const 用Y户HID = UUID;
	const 加J密M方F式S = 'none';
	
	const 传C输S层C协X议Y = 'ws';
	const 伪W装Z域Y名M = 域Y名M地D址Z;
	const 路L径J = path;
	
	let 传C输S层C安A全Q = ['tls',true];
	const SNI = 域Y名M地D址Z;
	const 指Z纹W = 'randomized';

	if (域Y名M地D址Z.includes('.workers.dev')){
		地D址Z = atob('dmlzYS5jbg==');
		端D口K = 80 ;
		传C输S层C安A全Q = ['',false];
	}

	const 威W图T瑞R = `${协X议Y类L型X}://${用Y户HID}@${地D址Z}:${端D口K}\u003f\u0065\u006e\u0063\u0072\u0079`+'p'+`${atob('dGlvbj0=') + 加J密M方F式S}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${传C输S层C安A全Q[0]}&sni=${SNI}&fp=${指Z纹W}&type=${传C输S层C协X议Y}&host=${伪W装Z域Y名M}&path=${encodeURIComponent(路L径J)}#${encodeURIComponent(别名)}`; 
	const 猫M猫M猫M = `- {name: ${FileName}, server: ${地D址Z}, port: ${端D口K}, type: ${协X议Y类L型X}, uuid: ${用Y户HID}, tls: ${传C输S层C安A全Q[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: true, servername: ${伪W装Z域Y名M}, client-fingerprint: ${指Z纹W}, network: ${传C输S层C协X议Y}, ws-opts: {path: "${路L径J}", headers: {${伪W装Z域Y名M}}}}`;
	return [威W图T瑞R,猫M猫M猫M];
}

let subParams = ['sub','base64','b64','clash','singbox','sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));

async function 生S成C配P置Z信X息X(userID, hostName, sub, UA, RproxyIP, _url, env) {
	spasswd = env.SPASSWD || '1QAZ';
	if (sub) {
		const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
		if (match) {
			sub = match[1];
		}
		const subs = await 整理(sub);
		if (subs.length > 1) sub = subs[0];
	} else {
		if (env.KV){
			await 迁Q移Y地D址Z列L表B(env);
			const 优Y选X地D址Z列L表B = await env.KV.get('ADD.txt');
			if (优Y选X地D址Z列L表B) {
				const 优Y选X地D址Z数S组Z = await 整理(优Y选X地D址Z列L表B);
				const 分F类L地Z址Z = {
					接J口K地D址Z: new Set(),
					链L接J地D址Z: new Set(),
					优Y选X地D址Z: new Set()
				};
				
				for (const 元素 of 优Y选X地D址Z数S组Z) {
					if (元素.startsWith('https://')) {
						分F类L地Z址Z.接J口K地D址Z.add(元素);
					} else if (元素.includes('://')) {
						分F类L地Z址Z.链L接J地D址Z.add(元素);
					} else {
						分F类L地Z址Z.优Y选X地D址Z.add(元素);
					}
				}
				
				adresespi = [...分F类L地Z址Z.接J口K地D址Z];
				林克 = [...分F类L地Z址Z.链L接J地D址Z];
				adreses = [...分F类L地Z址Z.优Y选X地D址Z];
			}
		}
		
		if ((adreses.length + adresespi.length + adnots.length + antai.length + adrescv.length) == 0){
			let cfips = [
				'103.21.244.0/23',
				'104.16.0.0/13',
				'104.24.0.0/14',
				'172.64.0.0/14',
				'103.21.244.0/23',
				'104.16.0.0/14',
				'104.24.0.0/15',
				'141.101.64.0/19',
				'172.64.0.0/14',
				'188.114.96.0/21',
				'190.93.240.0/21',
			];
	
			function generateRandomIPFromCIDR(cidr) {
				const [base, mask] = cidr.split('/');
				const baseIP = base.split('.').map(Number);
				const subnetMask = 32 - parseInt(mask, 10);
				const maxHosts = Math.pow(2, subnetMask) - 1;
				const randomHost = Math.floor(Math.random() * maxHosts);
	
				const randomIP = baseIP.map((octet, index) => {
					if (index < 2) return octet;
					if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
					return (octet & (255 << subnetMask)) + (randomHost & 255);
				});
	
				return randomIP.join('.');
			}
			adreses = adreses.concat('127.0.0.1:1234#CFnat');
			if (hostName.includes(".workers.dev")) {
				adnots = adnots.concat(cfips.map(cidr => generateRandomIPFromCIDR(cidr) + '#CF随机节点'));
			} else {
				adreses = adreses.concat(cfips.map(cidr => generateRandomIPFromCIDR(cidr) + '#CF随机节点'));
			}
		}
	}

	const uuid = (_url.pathname == `/${动态优优艾迪}`) ? 动态优优艾迪 : userID;
	const userAgent = UA.toLowerCase();
	const Config = 配p置z信x息x(userID , hostName);
	const vvv2aayy = Config[0];
	const clash = Config[1];
	let proxyhost = "";
	if(hostName.includes(".workers.dev")){
		if ( proyhstsUL && (!pryhsts || pryhsts.length == 0)) {
			try {
				const response = await fetch(proyhstsUL); 
			
				if (!response.ok) {
					console.error('获取地址时出错:', response.status, response.statusText);
					return; 
				}
			
				const text = await response.text();
				const lines = text.split('\n');
				const nnEptyLes = lines.filter(line => line.trim() !== '');
			
				pryhsts = pryhsts.concat(nnEptyLes);
			} catch (error) {
			}
		} 
		if (pryhsts.length != 0) proxyhost = pryhsts[Math.floor(Math.random() * pryhsts.length)] + "/";
	}

	if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		const newSocks5s = s0ks5s.map(sos5dess => {
			if (sos5dess.includes('@')) return sos5dess.split('@')[1];
			else if (sos5dess.includes('//')) return sos5dess.split('//')[1];
			else return sos5dess;
		});

		let sSck5Lst = '';
		if (gScks5s.length > 0 && eSs ) {
			sSck5Lst = `${decodeURIComponent('SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
			if (gScks5s.includes(atob('YWxsIGlu'))||gScks5s.includes(atob('Kg=='))) sSck5Lst += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
			else sSck5Lst += `<br>&nbsp;&nbsp;${gScks5s.join('<br>&nbsp;&nbsp;')}<br>`;
		}

		let 订D阅Y器Q = '<br>';
		if (sub) {
			if (eSs) 订D阅Y器Q += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${sSck5Lst}`;
			else if (prxyIP && prxyIP != '') 订D阅Y器Q += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${prxyIs.join('<br>&nbsp;&nbsp;')}<br>`;
			else if (RproxyIP == 'true') 订D阅Y器Q += `CFCDN（访问方式）: 自动获取ProxyIP<br>`;
			else 订D阅Y器Q += `CFCDN（访问方式）: 无法访问, 需要您设置 prxyIP/PROXYIP ！！！<br>`
			订D阅Y器Q += `<br>SUB（优选订阅生成器）: ${sub}`;
		} else {
			if (eSs) 订D阅Y器Q += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${sSck5Lst}`;
			else if (prxyIP && prxyIP != '') 订D阅Y器Q += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${prxyIs.join('<br>&nbsp;&nbsp;')}<br>`;
			else 订D阅Y器Q += `CFCDN（访问方式）: 无法访问, 需要您设置 prxyIP/PROXYIP ！！！<br>`;
			let 判断是否绑定KV空间 = '';
			if (env.KV) 判断是否绑定KV空间 = ` <a href='${_url.pathname}/edit'>编辑优选列表</a>`;
			订D阅Y器Q += `<br>您的订阅内容由 内置 adreses/ADD* 参数变量提供${判断是否绑定KV空间}<br>`;
			if (adreses.length > 0) 订D阅Y器Q += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${adreses.join('<br>&nbsp;&nbsp;')}<br>`;
			if (adnots.length > 0) 订D阅Y器Q += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${adnots.join('<br>&nbsp;&nbsp;')}<br>`;
			if (adresespi.length > 0) 订D阅Y器Q += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${adresespi.join('<br>&nbsp;&nbsp;')}<br>`;
			if (antai.length > 0) 订D阅Y器Q += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${antai.join('<br>&nbsp;&nbsp;')}<br>`;
			if (adrescv.length > 0) 订D阅Y器Q += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${adrescv.join('<br>&nbsp;&nbsp;')}<br>`;
		}

		if (动态优优艾迪 && _url.pathname !== `/${动态优优艾迪}`) 订D阅Y器Q = '';
		else 订D阅Y器Q += `<br>SUBAPI（订阅转换后端）: ${sPtl}://${subConverter}<br>SUBCONFIG（订阅转换配置文件）: ${subConfig}`;
		const 动态优优艾迪信息 = (uuid != userID) ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${usIDLw}<br>${uerDTie}TIME（动态优优艾迪有效时间）: ${有Y效X时S间J} 天<br>UPTIME（动态优优艾迪更新时间）: ${更G新X时S间J} 时（北京时间）<br><br>` : `${uerDTie}`;
		const 节点配置页 = `
			################################################################<br>
			Subscribe / sub 订阅地址, 支持 Base64、clash-meta、sing-box 订阅格式<br>
			---------------------------------------------------------------<br>
			自适应订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sub</a><br>
			<br>
			Base64订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?base64')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?base64</a><br>
			<br>
			clash订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
			<br>
			singbox订阅地址:<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?singbox')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?singbox</a><br>
			<br>
			<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">实用订阅技巧∨</a></strong><br>
				<div id="noticeContent" class="notice-content" style="display: none;">
					<strong>1.</strong> 如您使用的是 PassWall、SSR+ 等路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br>
					<br>
					<strong>2.</strong> 快速切换 <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
					<br>
					<strong>3.</strong> 快速更换 PROXYIP 至：proxyip.fxxk.dedyn.io:443，您可将"?proxyip=proxyip.fxxk.dedyn.io:443"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp; https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.fxxk.dedyn.io:443</strong><br>
					<br>
					<strong>4.</strong> 快速更换 SOCKS5 至：user:password@127.0.0.1:1080，您可将"?socks5=user:password@127.0.0.1:1080"参数添加到链接末尾，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
					<br>
					<strong>5.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
					&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.fxxk.dedyn.io<br>
				</div>
			<script>
			function copyToClipboard(text) {
				navigator.clipboard.writeText(text).then(() => {
					alert('已复制到剪贴板');
				}).catch(err => {
					console.error('复制失败:', err);
				});
			}

			function toggleNotice() {
				const noticeContent = document.getElementById('noticeContent');
				const noticeToggle = document.getElementById('noticeToggle');
				if (noticeContent.style.display === 'none') {
					noticeContent.style.display = 'block';
					noticeToggle.textContent = '实用订阅技巧∧';
				} else {
					noticeContent.style.display = 'none'; 
					noticeToggle.textContent = '实用订阅技巧∨';
				}
			}
			</script>
			---------------------------------------------------------------<br>
			################################################################<br>
			${FileName} 配p置z信x息x<br>
			---------------------------------------------------------------<br>
			${动态优优艾迪信息}HOST: ${hostName}<br>
			UUID: ${userID}<br>
			FKID: ${feUD}<br>
			UA: ${UA}<br>
			${订D阅Y器Q}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			vvv2aayy<br>
			---------------------------------------------------------------<br>
			<a href="javascript:void(0)" onclick="copyToClipboard('${vvv2aayy}')" style="color:blue;text-decoration:underline;cursor:pointer;">${vvv2aayy}</a><br>
			---------------------------------------------------------------<br>
			################################################################<br>
			clash-meta<br>
			---------------------------------------------------------------<br>
			${clash}<br>
			---------------------------------------------------------------<br>
			################################################################<br>
			${cmad}
			`;
		return 节点配置页;
	} else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}

		let nAai = [];
		let nAc = [];
		let nAnta = [];
		let nAntc = [];

		if (hostName.includes(".workers.dev")){
			noTLS = 'true';
			fHN = `${fHN}.workers.dev`;
			nAnta = await 整Z理L优Y选X列L表B(antai);
			nAntc = await 整Z理L测C速S结J果G('FALSE');
		} else if (hostName.includes(".pages.dev")){
			fHN = `${fHN}.pages.dev`;
		} else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true'){
			noTLS = 'true';
			fHN = `notls${fHN}.net`;
			nAnta = await 整Z理L优Y选X列L表B(antai);
			nAntc = await 整Z理L测C速S结J果G('FALSE');
		} else {
			fHN = `${fHN}.xyz`
		}
		console.log(`虚假HOST: ${fHN}`);
		let url = `${sPtl}://${sub}/sub?host=${fHN}&uuid=${feUD + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}&spasswd=${spasswd}`;
		let isBase64 = true;

		if (!sub || sub == ""){
			if(hostName.includes('workers.dev')) {
				if (proyhstsUL && (!pryhsts || pryhsts.length == 0)) {
					try {
						const response = await fetch(proyhstsUL); 
					
						if (!response.ok) {
							console.error('获取地址时出错:', response.status, response.statusText);
							return; 
						}
					
						const text = await response.text();
						const lines = text.split('\n');

						const nnEptyLes = lines.filter(line => line.trim() !== '');
					
						pryhsts = pryhsts.concat(nnEptyLes);
					} catch (error) {
						console.error('获取地址时出错:', error);
					}
				}
				pryhsts = [...new Set(pryhsts)];
			}
	
			nAai = await 整Z理L优Y选X列L表B(adresespi);
			nAc = await 整Z理L测C速S结J果G('TRUE');
			url = `https://${hostName}/${feUD + _url.search}`;
			if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
				if (_url.search) url += '&notls';
				else url += '?notls';
			}
			console.log(`虚假订阅: ${url}`);
		} 

		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())){
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || ( _url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `${sPtl}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true&spasswd=${spasswd}`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || (( _url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `${sPtl}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true&spasswd=${spasswd}`;
				isBase64 = false;
			}
		}
		
		try {
			let content;
			if ((!sub || sub == "") && isBase64 == true) {
				content = await 生S成C本B地D订D阅Y(fHN,feUD,noTLS,nAai,nAc,nAnta,nAntc);
			} else {
				const response = await fetch(url ,{
					headers: {
						'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
					}});
				content = await response.text();
			}

			if (_url.pathname == `/${feUD}`) return content;

			return 恢H复F伪W装Z信X息X(content, userID, hostName, isBase64);

		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}
	}
}

async function 整Z理L优Y选X列L表B(api) {
	if (!api || api.length === 0) return [];

	let newapi = "";


	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort(); 
	}, 2000); 

	try {
		const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
			method: 'get', 
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
			},
			signal: controller.signal 
		}).then(response => response.ok ? response.text() : Promise.reject())));

		for (const [index, response] of responses.entries()) {
			if (response.status === 'fulfilled') {
				const content = await response.value;

				const lines = content.split(/\r?\n/);
				let 节J点D备B注Z = '';
				let 测速端口 = '443';

				if (lines[0].split(',').length > 3){
					const idMatch = api[index].match(/id=([^&]*)/);
					if (idMatch) 节J点D备B注Z = idMatch[1];

					const portMatch = api[index].match(/port=([^&]*)/);
					if (portMatch) 测速端口 = portMatch[1];
					
					for (let i = 1; i < lines.length; i++) {
						const columns = lines[i].split(',')[0];
						if(columns){
							newapi += `${columns}:${测速端口}${节J点D备B注Z ? `#${节J点D备B注Z}` : ''}\n`;
							if (api[index].includes('proxyip=true')) poyIPPol.push(`${columns}:${测速端口}`);
						}
					}
				} else {
					if (api[index].includes('proxyip=true')) {
						poyIPPol = poyIPPol.concat((await 整理(content)).map(item => {
							const baseItem = item.split('#')[0] || item;
							if (baseItem.includes(':')) {
								const port = baseItem.split(':')[1];
								if (!htpPts.includes(port)) {
									return baseItem;
								}
							} else {
								return `${baseItem}:443`;
							}
							return null; 
						}).filter(Boolean));
					}
					newapi += content + '\n';
				}
			}
		}
	} catch (error) {
		console.error(error);
	} finally {

		clearTimeout(timeout);
	}
	const nAai = await 整理(newapi);
	return nAai;
}

async function 整Z理L测C速S结J果G(tls) {
	if (!adrescv || adrescv.length === 0) {
		return [];
	}
	
	let nAc = [];
	
	for (const csvUrl of adrescv) {
		try {
			const response = await fetch(csvUrl);
		
			if (!response.ok) {
				console.error('获取CSV地址时出错:', response.status, response.statusText);
				continue;
			}
		
			const text = await response.text();
			let lines;
			if (text.includes('\r\n')){
				lines = text.split('\r\n');
			} else {
				lines = text.split('\n');
			}
		
			const header = lines[0].split(',');
			const tsIdx = header.indexOf('TLS');
			
			const iAIdx = 0;
			const ptIdx = 1;
			const daaCtrIdx = tsIdx + rmrkIdx; 
		
			if (tsIdx === -1) {
				console.error('CSV文件缺少必需的字段');
				continue;
			}
		
			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
				const sedIdx = columns.length - 1; 
				if (columns[tsIdx].toUpperCase() === tls && parseFloat(columns[sedIdx]) > DLS) {
					const ipAddress = columns[iAIdx];
					const port = columns[ptIdx];
					const dataCenter = columns[daaCtrIdx];
			
					const fomtedArss = `${ipAddress}:${port}#${dataCenter}`;
					nAc.push(fomtedArss);
					if (csvUrl.includes('proxyip=true') && columns[tsIdx].toUpperCase() == 'true' && !htpPts.includes(port)) {
						poyIPPol.push(`${ipAddress}:${port}`);
					}
				}
			}
		} catch (error) {
			console.error('获取CSV地址时出错:', error);
			continue;
		}
	}
	
	return nAc;
}

function 生S成C本B地D订D阅Y(host,UUID,noTLS,nAai,nAc,nAnta,nAntc) {
	const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
	adreses = adreses.concat(nAai);
	adreses = adreses.concat(nAc);
	let ntsrespBy ;
	if (noTLS == 'true'){
		adnots = adnots.concat(nAnta);
		adnots = adnots.concat(nAntc);
		const uAnots = [...new Set(adnots)];

		ntsrespBy = uAnots.map(address => {
			let port = "-1";
			let addressid = address;
		
			const match = addressid.match(regex);
			if (!match) {
				if (address.includes(':') && address.includes('#')) {
					const parts = address.split(':');
					address = parts[0];
					const subParts = parts[1].split('#');
					port = subParts[0];
					addressid = subParts[1];
				} else if (address.includes(':')) {
					const parts = address.split(':');
					address = parts[0];
					port = parts[1];
				} else if (address.includes('#')) {
					const parts = address.split('#');
					address = parts[0];
					addressid = parts[1];
				}
			
				if (addressid.includes(':')) {
					addressid = addressid.split(':')[0];
				}
			} else {
				address = match[1];
				port = match[2] || port;
				addressid = match[3] || address;
			}

			const httpPorts = ["8080","8880","2052","2082","2086","2095"];
			if (!isVidIv4(address) && port == "-1") {
				for (let httpPort of httpPorts) {
					if (address.includes(httpPort)) {
						port = httpPort;
						break;
					}
				}
			}
			if (port == "-1") port = "80";
			
			let 伪W装Z域Y名M = host ;
			let 最Z终Z路L径J = path ;
			let 节J点D备B注Z = '';
			const 协X议Y类L型X = atob(啥S啥S啥_写X的D这Z是S啥S啊A);
			
			const 维列斯林克 = `${协X议Y类L型X}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==') + 伪W装Z域Y名M}&path=${encodeURIComponent(最Z终Z路L径J)}#${encodeURIComponent(addressid + 节J点D备B注Z)}`;
	
			return 维列斯林克;

		}).join('\n');

	}

	const uniqueAddresses = [...new Set(adreses)];

	const responseBody = uniqueAddresses.map(address => {
		let port = "-1";
		let addressid = address;

		const match = addressid.match(regex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressid = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressid = parts[1];
			}
		
			if (addressid.includes(':')) {
				addressid = addressid.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}

		if (!isVidIv4(address) && port == "-1") {
			for (let htpPrt of htpPts) {
				if (address.includes(htpPrt)) {
					port = htpPrt;
					break;
				}
			}
		}
		if (port == "-1") port = "443";
		
		let 伪W装Z域Y名M = host ;
		let 最Z终Z路L径J = path ;
		let 节J点D备B注Z = '';
		const matchingProxyIP = poyIPPol.find(prxyIP => prxyIP.includes(address));
		if (matchingProxyIP) 最Z终Z路L径J += `&proxyip=${matchingProxyIP}`;
		
		if(pryhsts.length > 0 && (伪W装Z域Y名M.includes('.workers.dev'))) {
			最Z终Z路L径J = `/${伪W装Z域Y名M}${最Z终Z路L径J}`;
			伪W装Z域Y名M = pryhsts[Math.floor(Math.random() * pryhsts.length)];
			节J点D备B注Z = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
		}
		
		const 协X议Y类L型X = atob(啥S啥S啥_写X的D这Z是S啥S啊A);
		const 维列斯林克 = `${协X议Y类L型X}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==') + 伪W装Z域Y名M}&fp=random&type=ws&host=${伪W装Z域Y名M}&path=${encodeURIComponent(最Z终Z路L径J)}#${encodeURIComponent(addressid + 节J点D备B注Z)}`;
			
		return 维列斯林克;
	}).join('\n');

	let base64Response = responseBody; 
	if(noTLS == 'true') base64Response += `\n${ntsrespBy}`;
	if (林克.length > 0) base64Response += '\n' + 林克.join('\n');
	return btoa(base64Response);
}

async function 整理(内容) {
	var 替T换H后H的D内N容R = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替T换H后H的D内N容R.charAt(0) == ',') 替T换H后H的D内N容R = 替T换H后H的D内N容R.slice(1);
	if (替T换H后H的D内N容R.charAt(替T换H后H的D内N容R.length - 1) == ',') 替T换H后H的D内N容R = 替T换H后H的D内N容R.slice(0, 替T换H后H的D内N容R.length - 1);
	const 地D址Z数S组Z = 替T换H后H的D内N容R.split(',');
	
	return 地D址Z数S组Z;
}

async function sendMessage(type, ip, add_data = "") {
	if (!BoTken || !CatD) return;

	try {
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.ok) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}

		const url = `https://api.telegram.org/bot${BoTken}/sendMessage?chat_id=${CatD}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
		return fetch(url, {
			method: 'GET',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	} catch (error) {
		console.error('Error sending message:', error);
	}
}

function isVidIv4(address) {
	const ip4Rgx = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ip4Rgx.test(address);
}

function 生成动态优优艾迪(密钥) {
	const 时S区Q偏P移Y = 8; 
	const 起Q始S日R期Q = new Date(2007, 6, 7, 更G新X时S间J, 0, 0); 
	const 一Y周Z的D毫H秒M数S = 1000 * 60 * 60 * 24 * 有Y效X时S间J;

	function 获H取Q当D前Q周Z数S() {
		const 现X在Z = new Date();
		const 调T整Z后G的D现X在Z = new Date(现X在Z.getTime() + 时S区Q偏P移Y * 60 * 60 * 1000);
		const 时S间J差C = Number(调T整Z后G的D现X在Z) - Number(起Q始S日R期Q);
		return Math.ceil(时S间J差C / 一Y周Z的D毫H秒M数S);
	}

	function 生成优优艾迪(基础字符串) {
		const 哈H希X缓H冲C区Q = new TextEncoder().encode(基础字符串);
		return crypto.subtle.digest('SHA-256', 哈H希X缓H冲C区Q).then((哈希) => {
			const 哈H希X数S组Z = Array.from(new Uint8Array(哈希));
			const 十S六L进J制Z哈H希X = 哈H希X数S组Z.map(b => b.toString(16).padStart(2, '0')).join('');
			return `${十S六L进J制Z哈H希X.substr(0, 8)}-${十S六L进J制Z哈H希X.substr(8, 4)}-4${十S六L进J制Z哈H希X.substr(13, 3)}-${(parseInt(十S六L进J制Z哈H希X.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十S六L进J制Z哈H希X.substr(18, 2)}-${十S六L进J制Z哈H希X.substr(20, 12)}`;
		});
	}

	const 当D前Q周Z数S = 获H取Q当D前Q周Z数S(); 
	const 结J束S时S间J = new Date(起Q始S日R期Q.getTime() + 当D前Q周Z数S * 一Y周Z的D毫H秒M数S);

	const 当前优优艾迪Promise = 生成优优艾迪(密钥 + 当D前Q周Z数S);
	const 上一个优优艾迪Promise = 生成优优艾迪(密钥 + (当D前Q周Z数S - 1));

	const 到D期Q时S间JUTC = new Date(结J束S时S间J.getTime() - 时S区Q偏P移Y * 60 * 60 * 1000); // UTC时间
	const 到D期Q时S间J字Z符F串C = `到期时间(UTC): ${到D期Q时S间JUTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结J束S时S间J.toISOString().slice(0, 19).replace('T', ' ')}\n`;

	return Promise.all([当前优优艾迪Promise, 上一个优优艾迪Promise, 到D期Q时S间J字Z符F串C]);
}

async function 迁Q移Y地D址Z列L表B(env, txt = 'ADD.txt') {
	const 旧J数S据J = await env.KV.get(`/${txt}`);
	const 新X数S据J = await env.KV.get(txt);
	
	if (旧J数S据J && !新X数S据J) {
		await env.KV.put(txt, 旧J数S据J);
		await env.KV.delete(`/${txt}`);
		return true;
	}
	return false;
}

async function KV(request, env, txt = 'ADD.txt') {
	try {

		if (request.method === "POST") {
			if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
			try {
				const content = await request.text();
				await env.KV.put(txt, content);
				return new Response("保存成功");
			} catch (error) {
				console.error('保存KV时发生错误:', error);
				return new Response("保存失败: " + error.message, { status: 500 });
			}
		}
		
		let content = '';
		let hasKV = !!env.KV;
		
		if (hasKV) {
			try {
				content = await env.KV.get(txt) || '';
			} catch (error) {
				console.error('读取KV时发生错误:', error);
				content = '读取数据时发生错误: ' + error.message;
			}
		}
		
		const html = `
			<!DOCTYPE html>
			<html>
			<head>
				<title>优选订阅列表</title>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<style>
					body {
						margin: 0;
						padding: 15px; /* 调整padding */
						box-sizing: border-box;
						font-size: 13px; /* 设置全局字体大小 */
					}
					.editor-container {
						width: 100%;
						max-width: 100%;
						margin: 0 auto;
					}
					.editor {
						width: 100%;
						height: 520px; /* 调整高度 */
						margin: 15px 0; /* 调整margin */
						padding: 10px; /* 调整padding */
						box-sizing: border-box;
						border: 1px solid #ccc;
						border-radius: 4px;
						font-size: 13px;
						line-height: 1.5;
						overflow-y: auto;
						resize: none;
					}
					.save-container {
						margin-top: 8px; /* 调整margin */
						display: flex;
						align-items: center;
						gap: 10px; /* 调整gap */
					}
					.save-btn, .back-btn {
						padding: 6px 15px; /* 调整padding */
						color: white;
						border: none;
						border-radius: 4px;
						cursor: pointer;
					}
					.save-btn {
						background: #4CAF50;
					}
					.save-btn:hover {
						background: #45a049;
					}
					.back-btn {
						background: #666;
					}
					.back-btn:hover {
						background: #555;
					}
					.save-status {
						color: #666;
					}
					.notice-content {
						display: none;
						margin-top: 10px;
						font-size: 13px;
						color: #333;
					}
				</style>
			</head>
			<body>
				################################################################<br>
				${FileName} 优选订阅列表:<br>
				---------------------------------------------------------------<br>
				&nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
				<div id="noticeContent" class="notice-content">
					${decodeURIComponent(atob('JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZyZWZzJTJGaGVhZHMlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U='))}
				</div>
				<div class="editor-container">
					${hasKV ? `
					<textarea class="editor" 
						placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
						id="content">${content}</textarea>
					<div class="save-container">
						<button class="back-btn" onclick="goBack()">返回配置页</button>
						<button class="save-btn" onclick="saveContent(this)">保存</button>
						<span class="save-status" id="saveStatus"></span>
					</div>
					<br>
					################################################################<br>
					${cmad}
					` : '<p>未绑定KV空间</p>'}
				</div>
		
				<script>
				if (document.querySelector('.editor')) {
					let timer;
					const textarea = document.getElementById('content');
					const originalContent = textarea.value;
		
					function goBack() {
						const currentUrl = window.location.href;
						const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
						window.location.href = parentUrl;
					}
		
					function replaceFullwidthColon() {
						const text = textarea.value;
						textarea.value = text.replace(/：/g, ':');
					}
					
					function saveContent(button) {
						try {
							const updateButtonText = (step) => {
								button.textContent = \`保存中: \${step}\`;
							};
							// 检测是否为iOS设备
							const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
							
							// 仅在非iOS设备上执行replaceFullwidthColon
							if (!isIOS) {
								replaceFullwidthColon();
							}
							updateButtonText('开始保存');
							button.disabled = true;
							// 获取textarea内容和原始内容
							const textarea = document.getElementById('content');
							if (!textarea) {
								throw new Error('找不到文本编辑区域');
							}
							updateButtonText('获取内容');
							let newContent;
							let originalContent;
							try {
								newContent = textarea.value || '';
								originalContent = textarea.defaultValue || '';
							} catch (e) {
								console.error('获取内容错误:', e);
								throw new Error('无法获取编辑内容');
							}
							updateButtonText('准备状态更新函数');
							const updateStatus = (message, isError = false) => {
								const statusElem = document.getElementById('saveStatus');
								if (statusElem) {
									statusElem.textContent = message;
									statusElem.style.color = isError ? 'red' : '#666';
								}
							};
							updateButtonText('准备按钮重置函数');
							const resetButton = () => {
								button.textContent = '保存';
								button.disabled = false;
							};
							if (newContent !== originalContent) {
								updateButtonText('发送保存请求');
								fetch(window.location.href, {
									method: 'POST',
									body: newContent,
									headers: {
										'Content-Type': 'text/plain;charset=UTF-8'
									},
									cache: 'no-cache'
								})
								.then(response => {
									updateButtonText('检查响应状态');
									if (!response.ok) {
										throw new Error(\`HTTP error! status: \${response.status}\`);
									}
									updateButtonText('更新保存状态');
									const now = new Date().toLocaleString();
									document.title = \`编辑已保存 \${now}\`;
									updateStatus(\`已保存 \${now}\`);
								})
								.catch(error => {
									updateButtonText('处理错误');
									console.error('Save error:', error);
									updateStatus(\`保存失败: \${error.message}\`, true);
								})
								.finally(() => {
									resetButton();
								});
							} else {
								updateButtonText('检查内容变化');
								updateStatus('内容未变化');
								resetButton();
							}
						} catch (error) {
							console.error('保存过程出错:', error);
							button.textContent = '保存';
							button.disabled = false;
							const statusElem = document.getElementById('saveStatus');
							if (statusElem) {
								statusElem.textContent = \`错误: \${error.message}\`;
								statusElem.style.color = 'red';
							}
						}
					}
		
					textarea.addEventListener('blur', saveContent);
					textarea.addEventListener('input', () => {
						clearTimeout(timer);
						timer = setTimeout(saveContent, 5000);
					});
				}
		
				function toggleNotice() {
					const noticeContent = document.getElementById('noticeContent');
					const noticeToggle = document.getElementById('noticeToggle');
					if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
						noticeContent.style.display = 'block';
						noticeToggle.textContent = '注意事项∧';
					} else {
						noticeContent.style.display = 'none';
						noticeToggle.textContent = '注意事项∨';
					}
				}
		
				// 初始化 noticeContent 的 display 属性
				document.addEventListener('DOMContentLoaded', () => {
					document.getElementById('noticeContent').style.display = 'none';
				});
				</script>
			</body>
			</html>
		`;
		
		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('处理请求时发生错误:', error);
		return new Response("服务器错误: " + error.message, { 
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}

define([
	"exports",
	"./events.js",
	"./apiclient.js",
	"./credentials.js",
	"./../common/servicelocator.js",
	"./../common/querystring.js",
	"./../common/usersettings/usersettings.js",
	"./../common/appsettings.js",
], function (
	_exports,
	_events,
	_apiclient,
	_credentials,
	_servicelocator,
	_querystring,
	_usersettings,
	_appsettings
) {
	Object.defineProperty(_exports, "__esModule", { value: !0 }),
		(_exports.default = void 0);
	const defaultTimeout = 2e4;
	let currentApiClient;
	function setCurrentApiClient(instance, apiClient) {
		instance.globalScopeApiClient && (globalThis.ApiClient = apiClient),
			(currentApiClient = apiClient);
	}
	const ConnectionMode = { Local: 0, Remote: 1, Manual: 2 };
	function getServerAddress(server, mode) {
		switch (mode) {
			case ConnectionMode.Local:
				return server.LocalAddress;
			case ConnectionMode.Manual:
				return server.ManualAddress;
			case ConnectionMode.Remote:
				return server.RemoteAddress;
			default:
				return (
					server.ManualAddress || server.LocalAddress || server.RemoteAddress
				);
		}
	}
	function mergeServers(credentialProvider, list1, list2) {
		let changed = !1;
		for (let i = 0, length = list2.length; i < length; i++)
			credentialProvider.addOrUpdateServer(list1, list2[i]) && (changed = !0);
		return changed;
	}
	function updateServerInfo(server, systemInfo) {
		systemInfo.ServerName && (server.Name = systemInfo.ServerName),
			systemInfo.Id && (server.Id = systemInfo.Id),
			systemInfo.LocalAddress &&
			(server.LocalAddress = systemInfo.LocalAddress),
			systemInfo.WanAddress && (server.RemoteAddress = systemInfo.WanAddress);
	}
	function getCapabilities() {
		const supportsSync = _servicelocator.appHost.supports("sync");
		return (
			supportsSync && _servicelocator.appHost.getSyncProfile
				? _servicelocator.appHost.getSyncProfile()
				: Promise.resolve(null)
		).then(function (deviceProfile) {
			let caps = {
				PlayableMediaTypes: ["Audio", "Video"],
				SupportedCommands: [
					"MoveUp",
					"MoveDown",
					"MoveLeft",
					"MoveRight",
					"PageUp",
					"PageDown",
					"PreviousLetter",
					"NextLetter",
					"ToggleOsd",
					"ToggleContextMenu",
					"Select",
					"Back",
					"SendKey",
					"SendString",
					"GoHome",
					"GoToSettings",
					"VolumeUp",
					"VolumeDown",
					"Mute",
					"Unmute",
					"ToggleMute",
					"SetVolume",
					"SetAudioStreamIndex",
					"SetSubtitleStreamIndex",
					"RefreshMediaSource",
					"DisplayContent",
					"GoToSearch",
					"DisplayMessage",
					"SetRepeatMode",
					"SetShuffle",
					"SetSubtitleOffset",
					"SetPlaybackRate",
					"ChannelUp",
					"ChannelDown",
					"PlayMediaSource",
					"PlayTrailers",
				],
				SupportsMediaControl: !0,
			};
			return (
				(caps.DeviceProfile = deviceProfile),
				(caps.IconUrl = _servicelocator.appHost.deviceIconUrl
					? _servicelocator.appHost.deviceIconUrl()
					: null),
				(caps.SupportsSync = supportsSync),
				(caps.SupportsContentUploading =
					_servicelocator.appHost.supports("cameraupload")),
				(caps = _servicelocator.appHost.getPushTokenInfo
					? Object.assign(caps, _servicelocator.appHost.getPushTokenInfo())
					: caps)
			);
		});
	}
	function getFetchPromise(request, signal) {
		if (signal && signal.aborted)
			return Promise.reject(
				(((err = new Error("AbortError")).name = "AbortError"), err)
			);
		var abortController,
			boundAbort,
			err = request.headers || {},
			fetchRequest =
				("json" === request.dataType && (err.accept = "application/json"),
					{ headers: err, method: request.type, credentials: "same-origin" });
		request.timeout &&
			((boundAbort = (abortController = new AbortController()).abort.bind(
				abortController
			)),
				signal && signal.addEventListener("abort", boundAbort),
				setTimeout(boundAbort, request.timeout),
				(signal = abortController.signal)),
			signal && (fetchRequest.signal = signal);
		let contentType = request.contentType;
		return (
			request.data &&
			("string" == typeof request.data
				? (fetchRequest.body = request.data)
				: ((fetchRequest.body = _querystring.default.paramsToString(
					request.data
				)),
					(contentType =
						contentType ||
						"application/x-www-form-urlencoded; charset=UTF-8"))),
			contentType && (err["Content-Type"] = contentType),
			fetch(request.url, fetchRequest)
		);
	}
	function sortServers(a, b) {
		return (b.DateLastAccessed || 0) - (a.DateLastAccessed || 0);
	}
	function setServerProperties(server) {
		server.Type = "Server";
	}
	function ajax(request, signal) {
		if (request)
			return (
				(request.headers = request.headers || {}),
				console.log("ConnectionManager requesting url: ".concat(request.url)),
				getFetchPromise(request, signal).then(
					(response) => (
						console.log(
							"ConnectionManager response status: "
								.concat(response.status, ", url: ")
								.concat(request.url)
						),
						response.status < 400
							? "json" === request.dataType
								? response.json()
								: "text" === request.dataType
									? response.text()
									: "application/json" === request.headers.accept
										? response.json()
										: 204 === response.status
											? response.text()
											: response
							: Promise.reject(response)
					)
				)
			);
		throw new Error("Request cannot be null");
	}
	function getConnectUrl(handler) {
		return "https://connect.emby.media/service/".concat(handler);
	}
	function replaceAll(originalString, strReplace, strWith) {
		strReplace = new RegExp(strReplace, "ig");
		return originalString.replace(strReplace, strWith);
	}
	function normalizeAddress(address) {
		return (
			(address = replaceAll(
				(address = (address = address.trim()).toLowerCase().startsWith("http")
					? address
					: (address.includes(":443") || address.includes(":8920")
						? "https://"
						: "http://"
					).concat(address)),
				"Http:",
				"http:"
			)),
			(address = replaceAll(address, "Https:", "https:"))
		);
	}
	function filterServers(servers, connectServers) {
		return servers.filter(
			(server) =>
				!server.ExchangeToken ||
				0 <
				connectServers.filter(
					(connectServer) => server.Id === connectServer.Id
				).length
		);
	}
	function compareVersions(a, b) {
		(a = a.split(".")), (b = b.split("."));
		for (let i = 0, length = Math.max(a.length, b.length); i < length; i++) {
			var aVal = parseInt(a[i] || "0"),
				bVal = parseInt(b[i] || "0");
			if (aVal < bVal) return -1;
			if (bVal < aVal) return 1;
		}
		return 0;
	}
	function onCredentialsSaved(e, data) {
		_events.default.trigger(this, "credentialsupdated", [data]);
	}
	function addAppInfoToConnectRequest(instance, request) {
		(request.headers = request.headers || {}),
			(request.headers["X-Application"] = ""
				.concat(instance.appName(), "/")
				.concat(instance.appVersion()));
	}
	function exchangePinInternal(instance, pinInfo) {
		if (pinInfo)
			return (
				addAppInfoToConnectRequest(
					instance,
					(instance = {
						type: "POST",
						url: getConnectUrl("pin/authenticate"),
						data: { deviceId: pinInfo.DeviceId, pin: pinInfo.Pin },
						dataType: "json",
					})
				),
				ajax(instance)
			);
		throw new Error("pinInfo cannot be null");
	}
	function getCacheKey(feature, apiClient, argument_2) {
		var viewOnly = (
			2 < arguments.length && void 0 !== argument_2 ? argument_2 : {}
		).viewOnly;
		let cacheKey = "regInfo-".concat(apiClient.serverId());
		return viewOnly && (cacheKey += "-viewonly"), cacheKey;
	}
	function onConnectUserSignIn(instance, user) {
		(instance._connectUser = user),
			_events.default.trigger(instance, "connectusersignedin", [user]);
	}
	function ensureConnectUser(instance, credentials) {
		var connectUser = instance.connectUser();
		return (!connectUser || connectUser.Id !== credentials.ConnectUserId) &&
			credentials.ConnectUserId &&
			credentials.ConnectAccessToken
			? ((instance._connectUser = null),
				(function (instance, userId, accessToken) {
					if (!userId) throw new Error("null userId");
					if (accessToken)
						return ajax({
							type: "GET",
							url: "https://connect.emby.media/service/user?id=".concat(userId),
							dataType: "json",
							headers: {
								"X-Application": ""
									.concat(instance.appName(), "/")
									.concat(instance.appVersion()),
								"X-Connect-UserToken": accessToken,
							},
						});
					throw new Error("null accessToken");
				})(
					instance,
					credentials.ConnectUserId,
					credentials.ConnectAccessToken
				).then(
					(user) => (onConnectUserSignIn(instance, user), Promise.resolve()),
					() => Promise.resolve()
				))
			: Promise.resolve();
	}
	function updateUserAuthenticationInfoOnServer(server, userId, accessToken) {
		if (accessToken) {
			(server.UserId = userId),
				(server.AccessToken = null),
				delete server.AccessToken;
			var users = (server.Users || []).slice(0);
			for (let i = 0, length = users.length; i < length; i++) {
				var user = users[i];
				if (user.UserId === userId)
					return void (user.AccessToken = accessToken);
			}
			users.push({ UserId: userId, AccessToken: accessToken }),
				(server.Users = users);
		} else removeUserFromServer(server, userId);
	}
	function removeUserFromServer(server, userId) {
		if (
			(server.UserId === userId && (server.UserId = null),
				(server.AccessToken = null),
				delete server.AccessToken,
				server.Users)
		) {
			var users = (server.Users || []).slice(0),
				list = [];
			for (let i = 0, length = users.length; i < length; i++) {
				var user = users[i];
				user.UserId !== userId && list.push(user);
			}
			server.Users = list;
		}
	}
	function clearUsersFromServer(server) {
		(server.UserId = null),
			(server.AccessToken = null),
			delete server.AccessToken,
			server.Users && (server.Users = []);
	}
	function getUserAuthInfoFromServer(server, userId) {
		if (server.Users) {
			var users = (server.Users || []).slice(0);
			for (let i = 0, length = users.length; i < length; i++) {
				var user = users[i];
				if (user.UserId === userId) return user;
			}
			return null;
		}
		return server.UserId === userId && server.AccessToken && !globalThis.appMode
			? { UserId: userId, AccessToken: server.AccessToken }
			: null;
	}
	function getLastUserAuthInfoFromServer(server) {
		return server.UserId
			? getUserAuthInfoFromServer(server, server.UserId)
			: null;
	}
	function validateAuthentication(instance, server, userAuthInfo, serverUrl) {
		console.log("connectionManager.validateAuthentication: " + serverUrl);
		const userId = userAuthInfo.UserId;
		return ajax({
			type: "GET",
			url: instance.getEmbyServerUrl(serverUrl, "System/Info", {
				api_key: userAuthInfo.AccessToken,
			}),
			dataType: "json",
		}).then(
			(systemInfo) => (updateServerInfo(server, systemInfo), systemInfo),
			() => (removeUserFromServer(server, userId), Promise.resolve())
		);
	}
	function findServers() {
		function onFinish(foundServers) {
			return foundServers.map(function (foundServer) {
				return {
					Id: foundServer.Id,
					LocalAddress:
						(function (info) {
							if (info.Address && info.EndpointAddress) {
								let address = info.EndpointAddress.split(":")[0];
								var info = info.Address.split(":");
								return (
									1 < info.length &&
									((info = info[info.length - 1]),
										isNaN(parseInt(info)) || (address += ":".concat(info))),
									normalizeAddress(address)
								);
							}
							return null;
						})(foundServer) || foundServer.Address,
					Name: foundServer.Name,
					LastConnectionMode: ConnectionMode.Local,
				};
			});
		}
		return _servicelocator.serverDiscovery
			.findServers(1e3)
			.then(onFinish, () => onFinish([]));
	}
	function validateServerAddressWithEndpoint(connectionManager, url, endpoint) {
		return ajax({
			url: connectionManager.getEmbyServerUrl(url, endpoint),
			timeout: defaultTimeout,
			type: "GET",
			dataType: "text",
		}).then(function (result) {
			var srch =
				String.fromCharCode(106) +
				String.fromCharCode(101) +
				String.fromCharCode(108) +
				String.fromCharCode(108) +
				String.fromCharCode(121) +
				String.fromCharCode(102);
			return (result || "").toLowerCase().includes(srch)
				? Promise.reject("serverversion")
				: Promise.resolve();
		});
	}
	function onAuthenticated(apiClient, result) {
		var options = {};
		const instance = this,
			credentials = _credentials.default.credentials();
		var servers = credentials.Servers.filter((s) => s.Id === result.ServerId);
		const server = servers.length ? servers[0] : apiClient.serverInfo();
		return (
			!1 !== options.updateDateLastAccessed &&
			(server.DateLastAccessed = Date.now()),
			(server.Id = result.ServerId),
			updateUserAuthenticationInfoOnServer(
				server,
				result.User.Id,
				result.AccessToken
			),
			_credentials.default.addOrUpdateServer(credentials.Servers, server) &&
			_credentials.default.credentials(credentials),
			(apiClient.enableAutomaticBitrateDetection =
				options.enableAutomaticBitrateDetection),
			apiClient.serverInfo(server),
			apiClient.setAuthenticationInfo(
				getUserAuthInfoFromServer(server, result.User.Id),
				(server.Users || []).slice(0)
			),
			(options.reportCapabilities = !0),
			afterConnected(instance, apiClient, server, options),
			apiClient.getPublicSystemInfo().then(function (systemInfo) {
				return (
					updateServerInfo(server, systemInfo),
					_credentials.default.addOrUpdateServer(credentials.Servers, server) &&
					_credentials.default.credentials(credentials),
					instance._getOrAddApiClient(server, apiClient.serverAddress()),
					onLocalUserSignIn(
						instance,
						server,
						apiClient,
						result.User.Id,
						apiClient.serverAddress()
					)
				);
			})
		);
	}
	function afterConnected(instance, apiClient, server, argument_3) {
		var options =
			3 < arguments.length && void 0 !== argument_3 ? argument_3 : {};
		(!0 !== options.reportCapabilities && !1 === options.reportCapabilities) ||
			!(function (instance, apiClient) {
				instance.reportCapabilities(apiClient);
			})(instance, apiClient),
			(apiClient.enableAutomaticBitrateDetection =
				options.enableAutomaticBitrateDetection),
			(apiClient.enableWebSocketAutoConnect = !1 !== options.enableWebSocket),
			apiClient.enableWebSocketAutoConnect &&
			(console.log("calling apiClient.ensureWebSocket"),
				(apiClient.connected = !0),
				apiClient.ensureWebSocket());
	}
	function onLocalUserSignIn(instance, server, apiClient, userId) {
		return (
			setCurrentApiClient(instance, apiClient),
			_usersettings.default.setUserInfo(userId, apiClient).then(() => {
				_events.default.trigger(instance, "localusersignedin", [
					server.Id,
					userId,
					apiClient,
				]);
			})
		);
	}
	function logoutOfServer(instance, apiClient) {
		const logoutInfo = { serverId: apiClient.serverId() };
		return apiClient.logout().then(
			() => {
				_usersettings.default.setUserInfo(null, null),
					_events.default.trigger(instance, "localusersignedout", [logoutInfo]);
			},
			() => {
				_usersettings.default.setUserInfo(null, null),
					_events.default.trigger(instance, "localusersignedout", [logoutInfo]);
			}
		);
	}
	function getConnectServers(instance, credentials) {
		return (
			console.log("Begin getConnectServers"),
			credentials.ConnectAccessToken && credentials.ConnectUserId
				? ajax({
					type: "GET",
					url: "https://connect.emby.media/service/servers?userId=".concat(
						credentials.ConnectUserId
					),
					dataType: "json",
					headers: {
						"X-Application": ""
							.concat(instance.appName(), "/")
							.concat(instance.appVersion()),
						"X-Connect-UserToken": credentials.ConnectAccessToken,
					},
				}).then(
					(servers) =>
						servers.map((i) => ({
							ExchangeToken: i.AccessKey,
							ConnectServerId: i.Id,
							Id: i.SystemId,
							Name: i.Name,
							RemoteAddress: i.Url,
							LocalAddress: i.LocalAddress,
						})),
					() => credentials.Servers.slice(0).filter((s) => s.ExchangeToken)
				)
				: Promise.resolve([])
		);
	}
	function tryReconnectToUrl(instance, url, connectionMode, delay, signal) {
		return (
			console.log("tryReconnectToUrl: " + url),
			(timeout = delay),
			new Promise(function (resolve) {
				setTimeout(resolve, timeout);
			}).then(() =>
				ajax(
					{
						url: instance.getEmbyServerUrl(url, "system/info/public"),
						timeout: defaultTimeout,
						type: "GET",
						dataType: "json",
					},
					signal
				).then((result) => ({
					url: url,
					connectionMode: connectionMode,
					data: result,
				}))
			)
		);
		var timeout;
	}
	function tryReconnect(instance, serverInfo, signal) {
		var addresses = [],
			addressesStrings = [];
		if (
			(serverInfo.ManualAddress &&
				((address = serverInfo.ManualAddress).includes("://127.0.0.1") ||
					!!address.toLowerCase().includes("://localhost")) &&
				!addressesStrings.includes(serverInfo.ManualAddress.toLowerCase()) &&
				(addresses.push({
					url: serverInfo.ManualAddress,
					mode: ConnectionMode.Manual,
				}),
					addressesStrings.push(
						addresses[addresses.length - 1].url.toLowerCase()
					)),
				serverInfo.ManualAddressOnly ||
				!serverInfo.LocalAddress ||
				addressesStrings.includes(serverInfo.LocalAddress.toLowerCase()) ||
				(addresses.push({
					url: serverInfo.LocalAddress,
					mode: ConnectionMode.Local,
				}),
					addressesStrings.push(
						addresses[addresses.length - 1].url.toLowerCase()
					)),
				serverInfo.ManualAddress &&
				!addressesStrings.includes(serverInfo.ManualAddress.toLowerCase()) &&
				(addresses.push({
					url: serverInfo.ManualAddress,
					mode: ConnectionMode.Manual,
				}),
					addressesStrings.push(
						addresses[addresses.length - 1].url.toLowerCase()
					)),
				serverInfo.ManualAddressOnly ||
				!serverInfo.RemoteAddress ||
				addressesStrings.includes(serverInfo.RemoteAddress.toLowerCase()) ||
				(addresses.push({
					url: serverInfo.RemoteAddress,
					mode: ConnectionMode.Remote,
				}),
					addressesStrings.push(
						addresses[addresses.length - 1].url.toLowerCase()
					)),
				console.log("tryReconnect: " + addressesStrings.join("|")),
				!addressesStrings.length)
		)
			return Promise.reject();
		const abortController = new AbortController();
		var address = abortController.abort.bind(abortController),
			promises =
				(signal && signal.addEventListener("abort", address),
					(signal = abortController.signal),
					[]);
		for (let i = 0, length = addresses.length; i < length; i++)
			promises.push(
				tryReconnectToUrl(
					instance,
					addresses[i].url,
					addresses[i].mode,
					200 * i,
					signal
				)
			);
		return Promise.any(promises).then(
			(result) => (abortController.abort(), result)
		);
	}
	function afterConnectValidated(
		instance,
		server,
		credentials,
		systemInfo,
		connectionMode,
		serverUrl,
		verifyLocalAuthentication,
		options
	) {
		console.log("connectionManager.afterConnectValidated: " + serverUrl);
		var userAuthInfo =
			((options = options || {}).userId
				? getUserAuthInfoFromServer(server, options.userId)
				: getLastUserAuthInfoFromServer(server)) || {};
		if (
			verifyLocalAuthentication &&
			userAuthInfo.UserId &&
			userAuthInfo.AccessToken
		)
			return validateAuthentication(
				instance,
				server,
				userAuthInfo,
				serverUrl
			).then((fullSystemInfo) =>
				afterConnectValidated(
					instance,
					server,
					credentials,
					fullSystemInfo || systemInfo,
					connectionMode,
					serverUrl,
					!1,
					options
				)
			);
		updateServerInfo(server, systemInfo),
			(server.LastConnectionMode = connectionMode),
			!1 !== options.updateDateLastAccessed &&
			(server.DateLastAccessed = Date.now()),
			_credentials.default.addOrUpdateServer(credentials.Servers, server) &&
			_credentials.default.credentials(credentials);
		const result = { Servers: [] };
		(result.ApiClient = instance._getOrAddApiClient(server, serverUrl)),
			result.ApiClient.setSystemInfo(systemInfo);
		let enableAutoLogin = options.enableAutoLogin;
		null == enableAutoLogin &&
			(enableAutoLogin = _appsettings.default.enableAutoLogin()),
			(result.State =
				userAuthInfo.UserId &&
					userAuthInfo.AccessToken &&
					!1 !== enableAutoLogin
					? "SignedIn"
					: "ServerSignIn"),
			result.Servers.push(server),
			(result.ApiClient.enableAutomaticBitrateDetection =
				options.enableAutomaticBitrateDetection),
			result.ApiClient.updateServerInfo(server, serverUrl),
			instance.resetRegistrationInfo(result.ApiClient, !0);
		function resolveActions() {
			return (
				_events.default.trigger(instance, "connected", [result]),
				Promise.resolve(result)
			);
		}
		return (
			console.log(
				"connectionManager.afterConnectValidated result.State: " +
				(result.State || "")
			),
			"SignedIn" === result.State
				? (afterConnected(instance, result.ApiClient, server, options),
					onLocalUserSignIn(
						instance,
						server,
						result.ApiClient,
						userAuthInfo.UserId
					).then(resolveActions, resolveActions))
				: resolveActions()
		);
	}
	function onSuccessfulConnection(
		instance,
		server,
		systemInfo,
		connectionMode,
		serverUrl,
		options
	) {
		console.log("connectionManager.onSuccessfulConnection: " + serverUrl);
		const credentials = _credentials.default.credentials();
		let enableAutoLogin = (options = options || {}).enableAutoLogin;
		return (
			null == enableAutoLogin &&
			(enableAutoLogin = _appsettings.default.enableAutoLogin()),
			credentials.ConnectAccessToken && !1 !== enableAutoLogin
				? ensureConnectUser(instance, credentials).then(() =>
					server.ExchangeToken
						? (function (instance, server, serverUrl, credentials) {
							if (!server.ExchangeToken)
								throw new Error("server.ExchangeToken cannot be null");
							var appName, appVersion, deviceName, deviceId;
							if (credentials.ConnectUserId)
								return (
									(credentials = {
										format: "json",
										ConnectUserId: credentials.ConnectUserId,
									}),
									(appName = instance.appName()),
									(appVersion = instance.appVersion()),
									(deviceName = instance.deviceName()),
									(deviceId = instance.deviceId()),
									appName && (credentials["X-Emby-Client"] = appName),
									deviceId && (credentials["X-Emby-Device-Id"] = deviceId),
									appVersion &&
									(credentials["X-Emby-Client-Version"] = appVersion),
									deviceName &&
									(credentials["X-Emby-Device-Name"] = deviceName),
									(credentials["X-Emby-Token"] = server.ExchangeToken),
									ajax({
										type: "GET",
										url: instance.getEmbyServerUrl(
											serverUrl,
											"Connect/Exchange",
											credentials
										),
										dataType: "json",
									}).then(
										(auth) => (
											updateUserAuthenticationInfoOnServer(
												server,
												auth.LocalUserId,
												auth.AccessToken
											),
											auth
										),
										() => (clearUsersFromServer(server), Promise.reject())
									)
								);
							throw new Error("credentials.ConnectUserId cannot be null");
						})(instance, server, serverUrl, credentials).then(
							() =>
								afterConnectValidated(
									instance,
									server,
									credentials,
									systemInfo,
									connectionMode,
									serverUrl,
									!0,
									options
								),
							() =>
								afterConnectValidated(
									instance,
									server,
									credentials,
									systemInfo,
									connectionMode,
									serverUrl,
									!0,
									options
								)
						)
						: afterConnectValidated(
							instance,
							server,
							credentials,
							systemInfo,
							connectionMode,
							serverUrl,
							!0,
							options
						)
				)
				: afterConnectValidated(
					instance,
					server,
					credentials,
					systemInfo,
					connectionMode,
					serverUrl,
					!0,
					options
				)
		);
	}
	function resolveIfAvailable(
		instance,
		url,
		server,
		result,
		connectionMode,
		options
	) {
		return (
			console.log("connectionManager.resolveIfAvailable: " + url),
			(function (instance, url) {
				return !1 === instance.enableServerAddressValidation
					? Promise.resolve()
					: Promise.all([
						validateServerAddressWithEndpoint(
							instance,
							url,
							"web/manifest.json"
						),
						validateServerAddressWithEndpoint(
							instance,
							url,
							"web/index.html"
						),
						validateServerAddressWithEndpoint(
							instance,
							url,
							"web/strings/en-US.json"
						),
					]);
			})(instance, url).then(
				() =>
					onSuccessfulConnection(
						instance,
						server,
						result,
						connectionMode,
						url,
						options
					),
				(err) =>
					"serverversion" === err
						? (console.log(
							"minServerVersion requirement not met. Server version: " +
							result.Version
						),
							{ State: "ServerUpdateNeeded", Servers: [server] })
						: {
							State: "Unavailable",
							Server: server,
							ConnectUser: instance.connectUser(),
						}
			)
		);
	}
	function onGetUserRecordFromAuthenticationError(err) {
		return (
			console.log("Error in getUserRecordFromAuthentication: " + err),
			Promise.resolve(null)
		);
	}
	function getUserRecordFromAuthentication(user, apiClient) {
		return (
			user.UserId === apiClient.getCurrentUserId()
				? apiClient.getCurrentUser()
				: apiClient.getUser(user.UserId)
		).catch(onGetUserRecordFromAuthenticationError);
	}
	function onServerAddressChanged(e, data) {
		_events.default.trigger(this, "serveraddresschanged", [data]);
	}
	_exports.default = new (class {
		constructor() {
			(this._apiClients = []),
				(this._apiClientsMap = {}),
				console.log("Begin ConnectionManager constructor"),
				(this._appName = _servicelocator.appHost.appName()),
				(this._appVersion = _servicelocator.appHost.appVersion()),
				(this._deviceName = _servicelocator.appHost.deviceName()),
				(this._deviceId = _servicelocator.appHost.deviceId()),
				(this._minServerVersion = "4.7.12"),
				_events.default.on(
					_credentials.default,
					"credentialsupdated",
					onCredentialsSaved.bind(this)
				);
		}
		appName() {
			return this._appName;
		}
		appVersion() {
			return this._appVersion;
		}
		deviceName() {
			return this._deviceName;
		}
		deviceId() {
			return this._deviceId;
		}
		minServerVersion(val) {
			return val && (this._minServerVersion = val), this._minServerVersion;
		}
		connectUser() {
			return this._connectUser;
		}
		connectUserId() {
			return _credentials.default.credentials().ConnectUserId;
		}
		connectToken() {
			return _credentials.default.credentials().ConnectAccessToken;
		}
		getServerInfo(id) {
			return _credentials.default
				.credentials()
				.Servers.filter((s) => s.Id === id)[0];
		}
		getLastUsedServer() {
			var servers = _credentials.default.credentials().Servers;
			return servers.sort(sortServers), servers.length ? servers[0] : null;
		}
		getApiClientFromServerInfo(server, serverUrlToMatch) {
			(server.DateLastAccessed = Date.now()),
				null == server.LastConnectionMode &&
				server.ManualAddress &&
				(server.LastConnectionMode = ConnectionMode.Manual);
			var credentials = _credentials.default.credentials(),
				serverUrlToMatch =
					(_credentials.default.addOrUpdateServer(
						credentials.Servers,
						server,
						serverUrlToMatch
					) && _credentials.default.credentials(credentials),
						this._getOrAddApiClient(
							server,
							getServerAddress(server, server.LastConnectionMode)
						));
			return setCurrentApiClient(this, serverUrlToMatch), serverUrlToMatch;
		}
		clearData() {
			console.log("connection manager clearing data"),
				(this._connectUser = null);
			var credentials = _credentials.default.credentials();
			(credentials.ConnectAccessToken = null),
				(credentials.ConnectUserId = null),
				(credentials.Servers = []),
				_credentials.default.credentials(credentials);
		}
		currentApiClient() {
			var server;
			return (
				currentApiClient ||
				((server = this.getLastUsedServer()) &&
					(currentApiClient = setCurrentApiClient(
						this,
						this.getApiClient(server.Id)
					))),
				currentApiClient
			);
		}
		_getOrAddApiClient(server, serverUrl) {
			let apiClient = server.Id ? this.getApiClient(server.Id) : null;
			if (!apiClient && server.IsLocalServer)
				for (let i = 0, length = this._apiClients.length; i < length; i++) {
					var current = this._apiClients[i];
					if (current.serverInfo().IsLocalServer) {
						apiClient = current;
						break;
					}
				}
			var ApiClient;
			return (
				apiClient
					? server.Id &&
					(apiClient.serverId() ||
						(apiClient.serverInfo(server),
							apiClient.setAuthenticationInfo(
								getLastUserAuthInfoFromServer(server),
								(server.Users || []).slice(0)
							)),
						(this._apiClientsMap[server.Id] = apiClient))
					: ((ApiClient = _servicelocator.apiClientFactory),
						(apiClient = new ApiClient(
							serverUrl,
							this.appName(),
							this.appVersion(),
							this.deviceName(),
							this.deviceId(),
							this.devicePixelRatio
						)),
						(currentApiClient = currentApiClient || apiClient),
						this._apiClients.push(apiClient),
						apiClient.serverInfo(server),
						apiClient.setAuthenticationInfo(
							getLastUserAuthInfoFromServer(server),
							(server.Users || []).slice(0)
						),
						apiClient.serverId() &&
						(this._apiClientsMap[apiClient.serverId()] = apiClient),
						apiClient.setCurrentLocale(this.currentLocale),
						(apiClient.onAuthenticated = onAuthenticated.bind(this)),
						_events.default.trigger(this, "apiclientcreated", [apiClient]),
						_events.default.on(
							apiClient,
							"serveraddresschanged",
							onServerAddressChanged.bind(this)
						)),
				console.log("returning instance from getOrAddApiClient"),
				apiClient
			);
		}
		setCurrentLocale(value) {
			this.currentLocale = value;
			for (let i = 0, length = this._apiClients.length; i < length; i++)
				this._apiClients[i].setCurrentLocale(value);
		}
		logout(apiClient) {
			console.log("begin connectionManager loguot");
			var promises = [];
			const isLoggedIntoConnect = this.isLoggedIntoConnect();
			var apiClients =
				apiClient && !isLoggedIntoConnect
					? [apiClient]
					: this._apiClients.slice(0);
			const apiClientInfos = [];
			for (let i = 0, length = apiClients.length; i < length; i++) {
				var currApiClient = apiClients[i];
				currApiClient.accessToken() &&
					(promises.push(logoutOfServer(this, currApiClient)),
						apiClientInfos.push({
							userId: currApiClient.getCurrentUserId(),
							serverId: currApiClient.serverId(),
						}));
			}
			const instance = this;
			return Promise.all(promises).then(() => {
				var credentials = _credentials.default.credentials(),
					servers = credentials.Servers.slice(0);
				for (let i = 0, length = apiClientInfos.length; i < length; i++) {
					var server,
						apiClientInfo = apiClientInfos[i];
					const currentServerId = apiClientInfo.serverId;
					currentServerId &&
						(server = servers.filter((s) => s.Id === currentServerId)[0]) &&
						(isLoggedIntoConnect
							? clearUsersFromServer(server)
							: removeUserFromServer(server, apiClientInfo.userId),
							(server.ExchangeToken = null));
				}
				(credentials.Servers = servers),
					(credentials.ConnectAccessToken = null),
					(credentials.ConnectUserId = null),
					_credentials.default.credentials(credentials),
					(instance._connectUser = null);
			});
		}
		getSavedServers() {
			var servers;
			return _credentials.default
				? ((servers = _credentials.default
					.credentials()
					.Servers.slice(0)).forEach(setServerProperties),
					servers.sort(sortServers),
					servers)
				: (console.log(
					"A call was made to getSavedServers before connectionManager was initialized."
				),
					[]);
		}
		getAvailableServers() {
			console.log("Begin getAvailableServers");
			const credentials = _credentials.default.credentials();
			return Promise.all([
				getConnectServers(this, credentials),
				findServers(),
			]).then((responses) => {
				var connectServers = responses[0],
					responses = responses[1],
					servers = credentials.Servers.slice(0);
				let changed = !1;
				return (
					mergeServers(_credentials.default, servers, responses) &&
					(changed = !0),
					mergeServers(_credentials.default, servers, connectServers) &&
					(changed = !0),
					(servers = filterServers(servers, connectServers)).forEach(
						setServerProperties
					),
					servers.sort(sortServers),
					changed ||
					(JSON.stringify(servers) !== JSON.stringify(credentials.Servers) &&
						(changed = !0)),
					changed &&
					((credentials.Servers = servers),
						_credentials.default.credentials(credentials)),
					servers
				);
			});
		}
		connectToServers(servers, options) {
			console.log(
				"Begin connectToServers, with ".concat(servers.length, " servers")
			);
			var firstServer = servers.length ? servers[0] : null;
			return firstServer
				? this.connectToServer(firstServer, options).then(
					(result) => (
						"Unavailable" === result.State &&
						(result.State = "ServerSelection"),
						console.log(
							"resolving connectToServers with result.State: " + result.State
						),
						result
					)
				)
				: Promise.resolve({
					Servers: servers,
					State:
						servers.length || this.connectUser()
							? "ServerSelection"
							: "ConnectSignIn",
					ConnectUser: this.connectUser(),
				});
		}
		connectToServer(server, options) {
			console.log("begin connectToServer"), (options = options || {});
			const instance = this;
			return tryReconnect(this, server).then(
				(result) => {
					var serverUrl = result.url,
						connectionMode = result.connectionMode;
					return (
						(result = result.data),
						1 ===
							compareVersions(instance.minServerVersion(), result.Version) ||
							1 === compareVersions(result.Version, "8.0")
							? (console.log(
								"minServerVersion requirement not met. Server version: " +
								result.Version
							),
								{ State: "ServerUpdateNeeded", Servers: [server] })
							: (server.Id &&
								result.Id !== server.Id &&
								!1 !== instance.validateServerIds &&
								updateServerInfo(
									(server = { Id: result.Id, ManualAddress: serverUrl }),
									result
								),
								resolveIfAvailable(
									instance,
									serverUrl,
									server,
									result,
									connectionMode,
									options
								))
					);
				},
				function () {
					return {
						State: "Unavailable",
						Server: server,
						ConnectUser: instance.connectUser(),
					};
				}
			);
		}
		connectToAddress(address, options) {
			if (!address) return Promise.reject();
			address = normalizeAddress(address);
			const instance = this;
			var server = {
				ManualAddress: address,
				LastConnectionMode: ConnectionMode.Manual,
			};
			return this.connectToServer(server, options).catch(function () {
				return (
					console.log("connectToAddress ".concat(address, " failed")),
					Promise.resolve({
						State: "Unavailable",
						ConnectUser: instance.connectUser(),
						Server: { ManualAddress: address },
						Address: address,
					})
				);
			});
		}
		loginToConnect(username, password) {
			if (!username) return Promise.reject();
			if (!password) return Promise.reject();
			const instance = this;
			return ajax({
				type: "POST",
				url: "https://connect.emby.media/service/user/authenticate",
				data: { nameOrEmail: username, rawpw: password },
				dataType: "json",
				contentType: "application/x-www-form-urlencoded; charset=UTF-8",
				headers: {
					"X-Application": ""
						.concat(this.appName(), "/")
						.concat(this.appVersion()),
				},
			}).then((result) => {
				var credentials = _credentials.default.credentials();
				return (
					(credentials.ConnectAccessToken = result.AccessToken),
					(credentials.ConnectUserId = result.User.Id),
					_credentials.default.credentials(credentials),
					onConnectUserSignIn(instance, result.User),
					result
				);
			});
		}
		signupForConnect(options) {
			var email = options.email,
				username = options.username,
				password = options.password,
				passwordConfirm = options.passwordConfirm;
			return email && username && password
				? !passwordConfirm || password !== passwordConfirm
					? Promise.reject({ errorCode: "passwordmatch" })
					: ((passwordConfirm = {
						email: email,
						userName: username,
						rawpw: password,
					}),
						options.grecaptcha &&
						(passwordConfirm.grecaptcha = options.grecaptcha),
						ajax({
							type: "POST",
							url: "https://connect.emby.media/service/register",
							data: passwordConfirm,
							dataType: "json",
							contentType: "application/x-www-form-urlencoded; charset=UTF-8",
							headers: {
								"X-Application": ""
									.concat(this.appName(), "/")
									.concat(this.appVersion()),
								"X-CONNECT-TOKEN": "CONNECT-REGISTER",
							},
						})
							.catch((response) => response.json())
							.then((result) => {
								if (result && result.Status)
									return "SUCCESS" === result.Status
										? Promise.resolve(result)
										: Promise.reject({ errorCode: result.Status });
								Promise.reject();
							}))
				: Promise.reject({ errorCode: "invalidinput" });
		}
		getUserInvitations() {
			var connectToken = this.connectToken();
			if (!connectToken) throw new Error("null connectToken");
			if (this.connectUserId())
				return ajax({
					type: "GET",
					url: "https://connect.emby.media/service/servers?userId=".concat(
						this.connectUserId(),
						"&status=Waiting"
					),
					dataType: "json",
					headers: {
						"X-Connect-UserToken": connectToken,
						"X-Application": ""
							.concat(this.appName(), "/")
							.concat(this.appVersion()),
					},
				});
			throw new Error("null connectUserId");
		}
		deleteServer(serverId) {
			var server, connectToken, connectUserId;
			if (serverId)
				return (server = (server = _credentials.default
					.credentials()
					.Servers.filter((s) => s.Id === serverId)).length
					? server[0]
					: null).ConnectServerId &&
					((connectToken = this.connectToken()),
						(connectUserId = this.connectUserId()),
						connectToken) &&
					connectUserId
					? ajax({
						type: "DELETE",
						url: "https://connect.emby.media/service/serverAuthorizations?serverId="
							.concat(server.ConnectServerId, "&userId=")
							.concat(connectUserId),
						headers: {
							"X-Connect-UserToken": connectToken,
							"X-Application": ""
								.concat(this.appName(), "/")
								.concat(this.appVersion()),
						},
					}).then(onDone, onDone)
					: onDone();
			throw new Error("null serverId");
			function onDone() {
				var credentials = _credentials.default.credentials();
				return (
					(credentials.Servers = credentials.Servers.filter(
						(s) => s.Id !== serverId
					)),
					_credentials.default.credentials(credentials),
					Promise.resolve()
				);
			}
		}
		resetRegistrationInfo(apiClient, onlyResetIfFailed) {
			let removeAll = !1;
			var cacheKey = getCacheKey("themes", apiClient, { viewOnly: !0 }),
				regInfo = JSON.parse(
					_servicelocator.appStorage.getItem(cacheKey) || "{}"
				);
			(!removeAll && onlyResetIfFailed && -1 !== regInfo.lastValidDate) ||
				(_servicelocator.appStorage.removeItem(cacheKey), (removeAll = !0)),
				(cacheKey = getCacheKey("themes", apiClient, { viewOnly: !1 })),
				(regInfo = JSON.parse(
					_servicelocator.appStorage.getItem(cacheKey) || "{}"
				)),
				(!removeAll && onlyResetIfFailed && -1 !== regInfo.lastValidDate) ||
				(_servicelocator.appStorage.removeItem(cacheKey), (removeAll = !0)),
				onlyResetIfFailed ||
				_events.default.trigger(this, "resetregistrationinfo");
		}
		getRegistrationInfo(feature, apiClient, options) {
			const params = {
				serverId: apiClient.serverId(),
				deviceId: this.deviceId(),
				deviceName: this.deviceName(),
				appName: this.appName(),
				appVersion: this.appVersion(),
			},
				cacheKey =
					((options = options || {}).viewOnly &&
						(params.viewOnly = options.viewOnly),
						getCacheKey(feature, apiClient, options));
			var feature = JSON.parse(
				_servicelocator.appStorage.getItem(cacheKey) || "{}"
			),
				timeSinceLastValidation = Date.now() - (feature.lastValidDate || 0);
			if (timeSinceLastValidation <= 864e5)
				return (
					console.log("getRegistrationInfo returning cached info"),
					Promise.resolve()
				);
			if (options.useCachedFailure && -1 === feature.lastValidDate)
				return Promise.reject();
			const regCacheValid =
				timeSinceLastValidation <= 864e5 * (feature.cacheExpirationDays || 7);
			return !params.serverId ||
				((options = apiClient.getCurrentUserId()) &&
					"81f53802ea0247ad80618f55d9b4ec3c" === options.toLowerCase() &&
					"21585256623b4beeb26d5d3b09dec0ac" === params.serverId.toLowerCase())
				? Promise.reject()
				: ((timeSinceLastValidation = ajax({
					url:
						"https://mb3admin.com/admin/service/registration/validateDevice?" +
						new URLSearchParams(params).toString(),
					type: "POST",
					dataType: "json",
				}).then(
					(response) => (
						_servicelocator.appStorage.setItem(
							cacheKey,
							JSON.stringify({
								lastValidDate: Date.now(),
								deviceId: params.deviceId,
								cacheExpirationDays: response.cacheExpirationDays,
								lastUpdated: Date.now(),
							})
						),
						Promise.resolve()
					),
					(response) => {
						_servicelocator.appStorage.setItem(
							cacheKey,
							JSON.stringify({
								lastValidDate: Date.now(),
								deviceId: params.deviceId,
								cacheExpirationDays: 999,
								lastUpdated: Date.now(),
							})
						),
							Promise.resolve()
					}
				)),
					regCacheValid
						? (console.log("getRegistrationInfo returning cached info"),
							Promise.resolve())
						: timeSinceLastValidation);
		}
		createPin() {
			var request = {
				type: "POST",
				url: getConnectUrl("pin"),
				data: { deviceId: this.deviceId() },
				dataType: "json",
			};
			return addAppInfoToConnectRequest(this, request), ajax(request);
		}
		getPinStatus(pinInfo) {
			if (pinInfo)
				return (
					(pinInfo = { deviceId: pinInfo.DeviceId, pin: pinInfo.Pin }),
					addAppInfoToConnectRequest(
						this,
						(pinInfo = {
							type: "GET",
							url: ""
								.concat(getConnectUrl("pin"), "?")
								.concat(new URLSearchParams(pinInfo).toString()),
							dataType: "json",
						})
					),
					ajax(pinInfo)
				);
			throw new Error("pinInfo cannot be null");
		}
		exchangePin(pinInfo) {
			if (!pinInfo) throw new Error("pinInfo cannot be null");
			const instance = this;
			return exchangePinInternal(this, pinInfo).then((result) => {
				var credentials = _credentials.default.credentials();
				return (
					(credentials.ConnectAccessToken = result.AccessToken),
					(credentials.ConnectUserId = result.UserId),
					_credentials.default.credentials(credentials),
					ensureConnectUser(instance, credentials)
				);
			});
		}
		connect(options) {
			console.log("Begin connect");
			const instance = this;
			return instance
				.getAvailableServers()
				.then((servers) => instance.connectToServers(servers, options));
		}
		handleMessageReceived(msg) {
			var serverId = msg.ServerId;
			if (serverId) {
				serverId = this.getApiClient(serverId);
				if (serverId) {
					if ("string" == typeof msg.Data)
						try {
							msg.Data = JSON.parse(msg.Data);
						} catch (err) {
							console.log(
								"Error in handleMessageReceived JSON.parse: ".concat(err)
							);
						}
					serverId.handleMessageReceived(msg);
				}
			}
		}
		onNetworkChanged() {
			var apiClients = this._apiClients;
			for (let i = 0, length = apiClients.length; i < length; i++)
				apiClients[i].onNetworkChanged();
		}
		onAppResume() {
			var apiClients = this._apiClients;
			for (let i = 0, length = apiClients.length; i < length; i++)
				apiClients[i].ensureWebSocket();
		}
		isLoggedIntoConnect() {
			return !(!this.connectToken() || !this.connectUserId());
		}
		isLoggedIn(serverId, userId) {
			var server = _credentials.default
				.credentials()
				.Servers.filter((s) => s.Id === serverId)[0];
			return (
				!!server &&
				null !=
				(null ==
					(userId = userId
						? getUserAuthInfoFromServer(server, userId)
						: getLastUserAuthInfoFromServer(server))
					? void 0
					: userId.AccessToken)
			);
		}
		getApiClients() {
			var servers = this.getSavedServers();
			for (let i = 0, length = servers.length; i < length; i++) {
				var serverUrl,
					server = servers[i];
				server.Id &&
					(serverUrl = getServerAddress(server, server.LastConnectionMode)) &&
					this._getOrAddApiClient(server, serverUrl);
			}
			return this._apiClients;
		}
		getApiClient(item) {
			if (!item) throw new Error("item or serverId cannot be null");
			let serverId = item.ServerId;
			serverId =
				serverId || (item.Id && "Server" === item.Type ? item.Id : item);
			let apiClient;
			if (serverId && (apiClient = this._apiClientsMap[serverId]))
				return apiClient;
			var apiClients = this._apiClients;
			for (let i = 0, length = apiClients.length; i < length; i++) {
				var apiClientServerId = (apiClient = apiClients[i]).serverId();
				if (!apiClientServerId || apiClientServerId === serverId)
					return apiClient;
			}
			return null;
		}
		getEmbyServerUrl(baseUrl, handler, params) {
			return _apiclient.default.getUrl(handler, params, baseUrl);
		}
		reportCapabilities(apiClient) {
			return getCapabilities().then(function (capabilities) {
				return apiClient.reportCapabilities(capabilities);
			});
		}
		getSignedInUsers(apiClient) {
			var credentials = _credentials.default.credentials(),
				serverId = apiClient.serverId(),
				servers = credentials.Servers.slice(0);
			let server;
			for (let i = 0, length = servers.length; i < length; i++)
				if (servers[i].Id === serverId) {
					server = servers[i];
					break;
				}
			if (!server) return Promise.resolve([]);
			var users = (server.Users || []).slice(0),
				promises = [];
			for (let i = 0, length = users.length; i < length; i++)
				promises.push(getUserRecordFromAuthentication(users[i], apiClient));
			return Promise.all(promises).then(function (responses) {
				var usersResult = [];
				for (let i = 0, length = responses.length; i < length; i++)
					responses[i] && usersResult.push(responses[i]);
				return usersResult;
			});
		}
		validateCanChangeToUser(apiClient, userId) {
			const credentials = _credentials.default.credentials();
			var serverId = apiClient.serverId(),
				servers = credentials.Servers.slice(0);
			let server;
			for (let i = 0, length = servers.length; i < length; i++)
				if (servers[i].Id === serverId) {
					server = servers[i];
					break;
				}
			if (!server) return Promise.reject();
			var users = (server.Users || []).slice(0);
			let user;
			for (let i = 0, length = users.length; i < length; i++)
				if (users[i].UserId === userId) {
					user = users[i];
					break;
				}
			return user
				? validateAuthentication(
					this,
					server,
					user,
					apiClient.serverAddress()
				).catch(function (err) {
					return (
						_credentials.default.addOrUpdateServer(
							credentials.Servers,
							server
						) && _credentials.default.credentials(credentials),
						Promise.reject(err)
					);
				})
				: Promise.reject();
		}
		changeToUser(apiClient, userId) {
			const instance = this;
			return this.validateCanChangeToUser(apiClient, userId).then(function () {
				var credentials = _credentials.default.credentials();
				const serverId = apiClient.serverId();
				var servers = credentials.Servers.slice(0);
				let server;
				for (let i = 0, length = servers.length; i < length; i++)
					if (servers[i].Id === serverId) {
						server = servers[i];
						break;
					}
				if (!server) return Promise.reject();
				var users = (server.Users || []).slice(0);
				let user;
				for (let i = 0, length = users.length; i < length; i++)
					if (users[i].UserId === userId) {
						user = users[i];
						break;
					}
				return user
					? getUserRecordFromAuthentication(user, apiClient).then(function (
						fullUserFromServer
					) {
						return onAuthenticated.call(instance, apiClient, {
							ServerId: serverId,
							User: fullUserFromServer,
							AccessToken: user.AccessToken,
						});
					})
					: Promise.reject();
			});
		}
	})();
});


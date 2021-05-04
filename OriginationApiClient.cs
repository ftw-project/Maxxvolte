// Property of SunGard© Data Systems Inc. or its affiliates, all rights reserved. SunGard Confidential

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using Ax.Core.Diagnostics;
using Ax.DependencyManagement;
using Ax.Frameworks.SysUtils;
using Ax.Mobile.Common.Helpers;
using Ax.Mobile.Common.Models;
using Ax.Mobile.Common.Resources;
using Ax.Mobile.Common.Services.Interfaces;
using Ax.Services.Client.Origination;
using Ax.Services.Common.Origination;
using Ax.Services.Data;
using Ax.Services.Data.Origination;
using Ax.Services.Data.Origination.Stateless;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Xamarin.Forms.Internals;

namespace Ax.Mobile.Common.Clients
{
	public class OriginationApiClient : IDisposable
	{
		private static readonly JsonNetSerializerOrigination serializer = new JsonNetSerializerOrigination();

		private readonly CookieContainer cookieContainer = new CookieContainer();
		private readonly CredentialCache credentialCache = new CredentialCache();

		protected HttpClient apiClient;
		protected HttpClientHandler requestHandler;
		protected LoggingHandler logHandler;

		private string antiForgeryTokenName;
		private string antiForgeryTokenValue;

		private byte[] pinnedCertHash;

		private static Lazy<OriginationApiClient> lazyClientInitializer = CreateClientLoader();

		public static OriginationApiClient Default => lazyClientInitializer.Value;

		public static OriginationApiClient Create(string url, TimeSpan? timeout = null)
		{
			return new OriginationApiClient(url, timeout);
		}

		private OriginationApiClient(string url, TimeSpan? timeout = null)
		{
			InitClient(url, timeout ?? TimeSpan.FromSeconds(300));

			Security = new SecurityApi(this);
			AssetType = new AssetTypeApi(this);
			Inbox = new InboxApi(this);
			Collections = new CollectionsApi(this);
			Contract = new ContractApi(this);
			Location = new LocationApi(this);
			LookupSet = new LookupSetApi(this);
			Note = new NoteApi(this);
			Party = new PartyApi(this);
			Workflow = new WorkflowApi(this);
			Print = new PrintApi(this);
			Document = new DocumentApi(this);
			System = new SystemApi(this);
			Task = new TaskApi(this);
			User = new UserApi(this);
			StatelessCalc = new StatelessCalcApi(this);
			DataUpload = new DataUploadApi(this);
			Globalization = new GlobalizationApi(this);
			ReceiptProcessing = new ReceiptProcessingApi(this);

			JsonConvert.DefaultSettings = () =>
			{
				var settings = new JsonSerializerSettings();
				settings.Converters.Add(new StringEnumConverter());
				settings.Converters.Add(new IsoDateTimeConverter {DateTimeFormat = "yyyy-MM-dd"});
				settings.Formatting = Formatting.Indented;
				return settings;
			};
		}

		private static Lazy<OriginationApiClient> CreateClientLoader()
		{
			return new Lazy<OriginationApiClient>(
				() =>
				{
					var settings = DependencyManager.Current.ResolveOrThrow<ISettingsService>();
					return new OriginationApiClient(settings.AafApiBaseUrl);
				});
		}

		public static async Task ResetDefaultClientAsync()
		{
			var cts = new CancellationTokenSource();
			try
			{
				if (Default.IsAuthenticated)
					await Default.Security.LogOff(cts.Token);
				lazyClientInitializer = CreateClientLoader();
				await Default.Security.LogOnOptions(cts.Token);
			}
			catch (OperationCanceledException)
			{
			}
		}

		public CookieContainer Cookies => cookieContainer;

		public Uri BaseUrl => apiClient?.BaseAddress;

		public OriginationNotificationsClient SignalR { get; private set; }

		public bool IsAuthenticated
		{
			// ReSharper disable ArrangeAccessorOwnerBody
			get
			{
				return !string.IsNullOrWhiteSpace(antiForgeryTokenName) &&
				       !string.IsNullOrWhiteSpace(antiForgeryTokenValue);
			}
			// ReSharper restore ArrangeAccessorOwnerBody
		}

		/// <summary>
		/// Gets or sets the value indicating whether Origination application is configured for SAML authentication.
		/// </summary>
		public bool IsSamlAuthentication { get; set; }

		/// <summary>
		/// Gets or sets the value indicating whether Origination API is accessible.
		/// </summary>
		public bool IsApiAvailable { get; set; }

		public string LoggedUserName { get; private set; }

		private void InitClient(string url, TimeSpan timeout)
		{
			if (string.IsNullOrWhiteSpace(url))
				throw new ArgumentException("url");

			if (!url.EndsWith("/"))
				url += "/";
			var uri = new Uri(url);

			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			ServicePointManager.ServerCertificateValidationCallback = (httpRequestMessage, certificate, chain, errors) =>
			{
				// The SSL cert handling should go through HttpClientHandler.ServerCertificateCustomValidationCallback
				// which is not implemented in monodroid right now

				if (certificate == null)
					return false;

				byte[] thumbprint = certificate.GetCertHash();
				if (pinnedCertHash != null && !pinnedCertHash.SequenceEqual(thumbprint))
				{
					LogHelper.LogWarning($"The following server certificate does not match pinned certificate used earlier: {certificate}");
					var msgSvc = DependencyManager.Current.ResolveOrThrow<IMessageService>();
					msgSvc.LongAlert(MobileResourceHelper.GetViewResource("ApiCertificateChangedError"));
					return false;
				}

				if (errors == SslPolicyErrors.None)
				{
					if (pinnedCertHash == null)
						pinnedCertHash = thumbprint; // Pin first valid certificate

					return true;
				}

				// Handle certificate errors
				if (!(httpRequestMessage is HttpWebRequest request))
					LogHelper.LogErrorFormat("Certificate error: {0}", errors);
				else
				{
					var sb = new StringBuilder(string.Format("Certificate error ({0}) while sending request to {1}", errors, request.RequestUri));
					try
					{
						sb
							.AppendLine("Certificate chain:");
						foreach (var cert in chain.ChainElements)
							sb
								.AppendLine($"{cert.ChainElementStatus} {cert.Information}")
								.AppendLine(cert.Certificate.ToString(true).Trim());
					}
					catch (NotImplementedException)
					{
					}
					finally
					{
						LogHelper.LogErrorFormat(sb.ToString());
					}
				}

				return false;
			};

			requestHandler = DependencyManager.Current.ResolveOrThrow<HttpClientHandler>();
			requestHandler.AllowAutoRedirect = true;
			requestHandler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
			requestHandler.CookieContainer = cookieContainer;
			requestHandler.Credentials = credentialCache;
			requestHandler.PreAuthenticate = true;
			requestHandler.UseCookies = true;

			logHandler = new LoggingHandler(uri, requestHandler);
			var appInfo = DependencyManager.Current.Resolve<IAppInfo>();
			string userAgentName, userAgentVersion;
			if (appInfo == null)
			{
				userAgentVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
				userAgentName = "OriginationApiMobileClient";
			}
			else
			{
				userAgentName = global::System.Text.RegularExpressions.Regex.Replace(appInfo.AppName, @"\s+", string.Empty);
				userAgentName = $"{userAgentName}MobileClient";
				userAgentVersion = appInfo.AppVersion;
			}

			apiClient = new HttpClient(logHandler)
			{
				BaseAddress = uri,
				Timeout = timeout,
				DefaultRequestHeaders =
				{
					ExpectContinue = false,
					UserAgent =
					{
						new ProductInfoHeaderValue(userAgentName, userAgentVersion)
					},
					Accept =
					{
						new MediaTypeWithQualityHeaderValue("application/json")
					},
					AcceptEncoding =
					{
						new StringWithQualityHeaderValue("gzip"),
						new StringWithQualityHeaderValue("deflate")
					},
					AcceptLanguage =
					{
						new StringWithQualityHeaderValue(CultureInfo.CurrentCulture.Name)
					}
				}
			};
			//apiClient.DefaultRequestHeaders.UserAgent.ParseAdd();
		}

		protected async Task<HttpResponseMessage> GetOptionsAsync(string apiPath, CancellationToken ct = default(CancellationToken))
		{
			HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Options, apiPath);
			HttpResponseMessage response = null;
			try
			{
				response = await apiClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
			}
			catch (InvalidOperationException ie)
			{
				AppCenterHelper.TrackError(
					ie, new Dictionary<string, string>
					{
						{"API", apiPath}
					});
			}
			catch (Exception e)
			{
				AppCenterHelper.TrackError(
					e, new Dictionary<string, string>
					{
						{"API", apiPath}
					});
			}

			return response;
		}

		protected async Task<ApiResponse<T>> CallApiAsync<T>(string apiPath, object data = null, HttpContent content = null, Action<LoadProgressChangedEventArgs> responseProgress = null, CancellationToken ct = default(CancellationToken), bool isRetry = false)
		{
			ct.ThrowIfCancellationRequested();
			bool throwOnError = ct != CancellationToken.None;
			string cancelReason = null;

			HttpResponseMessage response = null;
			HttpCompletionOption httpCompletion = responseProgress == null
				? HttpCompletionOption.ResponseContentRead
				: HttpCompletionOption.ResponseHeadersRead;
			content = content ?? new ApiJsonContent(data);
			try
			{
				response = await apiClient.SendAsync(new HttpRequestMessage(HttpMethod.Post, CreateUri(apiPath)) {Content = content}, httpCompletion, ct);

				if (IsAuthenticated && response.StatusCode == HttpStatusCode.Unauthorized)
					MessagingCenterHelper.Send(this, AxAppEvents.ApiSessionExpired, LoggedUserName);
				else if (IsAuthenticated && response.StatusCode == HttpStatusCode.Forbidden)
					cancelReason = response.ReasonPhrase;
				else if (response.StatusCode == HttpStatusCode.OK)
					MessagingCenterHelper.Send(this, AxAppEvents.ApiCalled, apiPath);
				//response.EnsureSuccessStatusCode();
				ct.ThrowIfCancellationRequested();
			}
			catch (ObjectDisposedException)
			{
				if (!isRetry)
					return await CallApiAsync<T>(apiPath, data, content, responseProgress, ct, true);

				cancelReason = MobileResourceHelper.GetViewResource("ApiUnaccessibleAlertMessage");
			}
			catch (HttpRequestException hrEx)
			{
				Exception rootEx = ExceptionHelper.GetInnerException(hrEx);
				if (rootEx is SocketException soEx && soEx.SocketErrorCode == SocketError.NetworkUnreachable)
				{
					// Offline mode
					var appCtx = DependencyManager.Current.Resolve<IAppContext>();
					if (appCtx != null)
					{
						MessagingCenterHelper.Send(appCtx, AxAppEvents.ConnectionChangeDetected, false);
						AppCenterHelper.TrackError(
							hrEx, new Dictionary<string, string>
							{
								{"API", apiPath}
							});
					}

					cancelReason = MobileResourceHelper.GetViewResource("DeviceOffline");
				}
				else if (hrEx.InnerException is WebException wEx)
				{
					if (wEx.Status == WebExceptionStatus.TrustFailure)
						cancelReason = MobileResourceHelper.GetViewResource("ApiUntrustedCertificateError");

					AppCenterHelper.TrackError(
						wEx, new Dictionary<string, string>
						{
							{"API", apiPath}
						});
				}
			}
			catch (Exception e)
			{
				AppCenterHelper.TrackError(
					e, new Dictionary<string, string>
					{
						{"API", apiPath}
					});
				var toast = DependencyManager.Current.ResolveOrThrow<IMessageService>();
				string error = ExceptionHelper.GetInnerException(e).Message;
				if (!throwOnError)
					toast.LongAlert(error);
				LogHelper.LogError(error);
				cancelReason = e.Message;
			}

			if (response?.StatusCode == HttpStatusCode.OK && content is ProgressDataContent progress)
				progress.Complete();

			ApiResponse<T> responseData = new ApiResponse<T>();
			if (response == null || !response.IsJsonResponse())
			{
				if (IsSamlAuthentication && response.IsHtmlResponse())
				{
					// In case of SAML, log off response may be text/html to redirect to IdP Logout URL.
					var textResponse = await response.Content.ReadAsStringAsync();
					return new ApiResponse<T>((T)(object)textResponse);
				}

				//To do later
				if(response.IsFileDownloadResponse())
				{
					FileInfoModel downloadData = await DownloadDataAsync(response, responseProgress, ct);
					return new ApiResponse<T>((T)(object)downloadData);
				}

				if (throwOnError && string.IsNullOrEmpty(cancelReason))
					cancelReason = MobileResourceHelper.GetViewResource("ApiResponseParseError");

				if (throwOnError)
					throw new OperationCanceledException(cancelReason, ct);

				return responseData;
			}

			if (response.Content.Headers.ContentLength > 0 || response.Content.Headers.ContentLength == null)
			{
				var toast = DependencyManager.Current.ResolveOrThrow<IMessageService>();
				try
				{
					using (var stream = await response.Content.ReadAsStreamAsync())
					using (var reader = new StreamReader(stream))
					using (var json = new JsonTextReader(reader))
					{
						if (reader.BaseStream.Length != 0)
							responseData = serializer.Deserialize<ApiResponse<T>>(json);
					}
				}
				catch (Exception e)
				{
					// ReSharper disable once ConditionIsAlwaysTrueOrFalse
					if (e != null)
					{
						AppCenterHelper.TrackError(
							e, new Dictionary<string, string>
							{
								{"API", apiPath}
							});

						string error = ExceptionHelper.GetInnerException(e).Message;
						if (!throwOnError)
							toast.LongAlert(error);
					}

					cancelReason = e.Message;
				}

				if (responseData != null && (responseData.Errors.Count > 0 || responseData.Warnings.Count > 0))
				{
					// There is an issue in Android when displaying multiline messages where line separator
					// is not exactly \r\n squence.
					var jointMessage = string.Join(MobileConsts.NewLine, responseData.Errors);
					cancelReason = jointMessage;

					if (responseData.Warnings.Count > 0)
					{
						var warnings = string.Join(MobileConsts.NewLine, responseData.Warnings);
						if (string.IsNullOrEmpty(cancelReason))
							toast.LongAlert(warnings, LogMessageType.Warning);
						else
							cancelReason = string.Join(MobileConsts.NewLine, cancelReason, warnings);
					}

					// If there is no cancellation token, display the error. If there is a cancellation token, the caller is responsible for displaying the error
					if (!throwOnError && !string.IsNullOrWhiteSpace(cancelReason))
						toast.LongAlert(jointMessage);
				}

				if (responseData != null)
				{
					if (!throwOnError && responseData.Infos.Count > 0)
						toast.LongAlert(string.Join(MobileConsts.NewLine, responseData.Infos), LogMessageType.Info);

					var requestValidation = responseData.Data as DCRequestValidation;
					if (requestValidation != null)
					{
						antiForgeryTokenName = requestValidation.TokenName;
						antiForgeryTokenValue = requestValidation.TokenValue;
						apiClient.DefaultRequestHeaders.Remove(antiForgeryTokenName);
						apiClient.DefaultRequestHeaders.Add(antiForgeryTokenName, antiForgeryTokenValue);
					}
				}
			}
			else if ((int)response.StatusCode >= 500)
			{
				cancelReason = response.ReasonPhrase;
				if (!throwOnError)
				{
					var toast = DependencyManager.Current.ResolveOrThrow<IMessageService>();
					toast.LongAlert(response.ReasonPhrase);
				}
			}

			if (throwOnError && !string.IsNullOrEmpty(cancelReason))
				throw new OperationCanceledException(cancelReason, ct);

			return responseData;
		}

		private static async Task<FileInfoModel> DownloadDataAsync(HttpResponseMessage response, Action<LoadProgressChangedEventArgs> progress = null, CancellationToken ct = default(CancellationToken))
		{
			byte[] downloadData;
			FileInfoModel result = DependencyManager.Current.ResolveOrThrow<FileInfoModel>();
			var contentDisposition = response.Content.Headers.ContentDisposition;
			string fileName = contentDisposition?.FileName ?? string.Empty;
			result.FileName = fileName;
			result.MimeType = response.Content.Headers.ContentType?.MediaType;

			using (var stream = await response.Content.ReadAsStreamAsync())
			{
				if (progress == null)
				{
					downloadData = FileHelper.StreamToByteArray(stream);
				}
				else
				{
					long totalBytes = response.Content.Headers.ContentLength ?? contentDisposition?.Size ?? 0L;
					long downloadedBytes = 0L;
					var buffer = new byte[8 * 4096];
					using (var ms = new MemoryStream())
					{
						while (true)
						{
							ct.ThrowIfCancellationRequested();
							var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, ct);
							if (bytesRead <= 0)
								break;

							downloadedBytes += bytesRead;
							var percent = totalBytes > 0 ? (int)(100.0 * downloadedBytes / totalBytes) : 0;
							progress(new LoadProgressChangedEventArgs(true, fileName, percent, downloadedBytes, totalBytes));

							await ms.WriteAsync(buffer, 0, bytesRead, ct);
						}

						downloadData = ms.ToArray();
					}

					ct.ThrowIfCancellationRequested();
					progress(
						new LoadProgressChangedEventArgs(true, fileName, 100, downloadedBytes, totalBytes)
						{
							IsCompleted = true
						});
				}
			}

			result.Data = downloadData;
			return result;
		}

		public void Dispose()
		{
			Dispose(false);
		}

		public void Dispose(bool disposeDefaultClient)
		{
			LogHelper.LogDebug("Disposing API client...");
			if (apiClient != null && IsAuthenticated)
			{
				try
				{
					global::System.Threading.Tasks.Task.Run(async () => await Security.LogOff()).Wait();
				}
				catch (Exception e)
				{
					AppCenterHelper.TrackError(e);
				}
			}

			logHandler?.Dispose();
			requestHandler?.Dispose();
			SignalR?.Dispose();
			apiClient?.Dispose();
			apiClient = null;

			if (disposeDefaultClient)
				lazyClientInitializer = CreateClientLoader();
		}

		public void InvalidateUserSession()
		{
			antiForgeryTokenName =
				antiForgeryTokenValue =
					LoggedUserName = null;
			foreach (Cookie cookie in Cookies.GetCookies(BaseUrl))
			{
				cookie.Expired = true;
				cookie.Expires = new DateTime(1999, 10, 12);
			}
		}

		public async Task SetupNotificationsAsync()
		{
			SignalR?.Dispose();
			SignalR = new OriginationNotificationsClient(this);
			await SignalR.ConnectAsync();
			await SignalR.GetAllNotificationsAsync(true);
		}

		private Uri CreateUri(string uri)
		{
			if (string.IsNullOrEmpty(uri))
				return null;
			return new Uri(uri, UriKind.RelativeOrAbsolute);
		}

		#region APIs

		public readonly AssetTypeApi AssetType;
		public readonly CollectionsApi Collections;
		public readonly ContractApi Contract;
		public readonly DataUploadApi DataUpload;
		public readonly DocumentApi Document;
		public readonly GlobalizationApi Globalization;
		public readonly InboxApi Inbox;
		public readonly LocationApi Location;
		public readonly LookupSetApi LookupSet;
		public readonly NoteApi Note;
		public readonly PartyApi Party;
		public readonly PrintApi Print;
		public readonly ReceiptProcessingApi ReceiptProcessing;
		public readonly SecurityApi Security;
		public readonly StatelessCalcApi StatelessCalc;
		public readonly SystemApi System;
		public readonly TaskApi Task;
		public readonly UserApi User;
		public readonly WorkflowApi Workflow;

		#endregion APIs

		#region API Definitions

		public abstract class BaseOriginationApi
		{
			protected readonly OriginationApiClient client;

			internal BaseOriginationApi(OriginationApiClient client)
			{
				this.client = client;
			}
		}

		public class SecurityApi : BaseOriginationApi
		{
			public Uri LogonUrl { get; }

			internal SecurityApi(OriginationApiClient client) : base(client)
			{
				LogonUrl = new Uri(client.apiClient.BaseAddress, "Security/LogOn");
			}

			public async Task<HttpResponseMessage> LogOnOptions(CancellationToken ct = default(CancellationToken))
			{
				var response = await client.GetOptionsAsync("SecurityApi", ct);
				if (response != null)
				{
					var authOptions = response.Headers.WwwAuthenticate;

					// ReSharper disable once ConditionIsAlwaysTrueOrFalse
					LogHelper.LogDebugFormat("API authentication options: {0}", string.Join(", ", authOptions.Select(h => h.Scheme)));

					client.IsSamlAuthentication = authOptions.Any(h => h.Scheme == "SAML");
				}

				client.IsApiAvailable = response != null && response.StatusCode == HttpStatusCode.OK;

				return response;
			}

			public async Task<DCRequestValidation> LogOn(DCLogOn args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCRequestValidation>("SecurityApi/LogOn", args, ct: ct);
				await ProcessLogonResponse(result?.Data);

				return result?.Data;
			}

			public async Task<DCRequestValidation> LogOnSso(CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCRequestValidation>("SecurityApi/LogOnSso", ct: ct);
				await ProcessLogonResponse(result?.Data);

				return result?.Data;
			}

			public async Task<DCSsoToken> GetSsoToken(DCSsoTokenGetArgs args)
			{
				var result = await client.CallApiAsync<DCSsoToken>("SecurityApi/GetSsoToken", args);
				return result.Data;
			}

			public async Task LogOff(CancellationToken ct = default(CancellationToken))
			{
				if (client.IsAuthenticated)
				{
					if (client.SignalR != null)
						await client.SignalR.DisconnectAsync();

					if (client.IsSamlAuthentication)
					{
						string result = (await client.CallApiAsync<string>("SecurityApi/LogOff", ct: ct)).Data;
						if (!string.IsNullOrEmpty(result))
						{
							try
							{
								// Parse SAML form
								XElement form = XElement.Parse(result).XPathSelectElement("//*[@id='samlform']");
								if (form != null)
								{
									string idpLogoutUrl = form.Attribute("action")?.Value;
									var formFields = form.Descendants().Where(d => d.Name.LocalName.Equals("input") && d.Attribute("type")?.Value == "hidden");
									var postData = formFields.ToDictionary(el => el.Attribute("name")?.Value, el => el.Attribute("value")?.Value);
									/*var idpResponse = */
									await client.apiClient.PostAsync(idpLogoutUrl, new FormUrlEncodedContent(postData), ct);
								}
							}
							catch (Exception e)
							{
								AppCenterHelper.TrackError(e);

								var toast = DependencyManager.Current.ResolveOrThrow<IMessageService>();
								string error = ExceptionHelper.GetInnerException(e).Message;
								toast.LongAlert(ExceptionHelper.GetInnerException(e).Message);
								LogHelper.LogError(error);
							}
						}
					}
					else
						await client.CallApiAsync<object>("SecurityApi/LogOff", ct: ct);
				}

				client.InvalidateUserSession();
			}

			private async Task ProcessLogonResponse(DCRequestValidation result)
			{
				if (result != null && !string.IsNullOrWhiteSpace(result.TokenName))
				{
					client.LoggedUserName = result.UserName;
					await client.SetupNotificationsAsync();
				}
			}
		}

		public class AssetTypeApi : BaseOriginationApi
		{
			internal AssetTypeApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCAssetTypeList> Browse(DCAssetTypeBrowseArgs args)
			{
				var result = await client.CallApiAsync<DCAssetTypeList>("AssetTypeApi/Browse", args);
				return result.Data;
			}

			public async Task<DCCollection<DCAssetTypeList>> GetForAssetHdr(DCAssetTypeGetForAssetHdrArgs args)
			{
				var result = await client.CallApiAsync<DCCollection<DCAssetTypeList>>("AssetTypeApi/GetForAssetHdr", args);
				return result.Data;
			}

			public async Task<DCAssetTypeItem> GetDefaultForProgram(DCAssetTypeGetDefaultForProgramArgs args)
			{
				var result = await client.CallApiAsync<DCAssetTypeItem>("AssetTypeApi/GetDefaultForProgram", args);
				return result.Data;
			}

			public async Task<DCPagedCollection<DCAssetTypeItem>> Search(DCAssetTypeSearchArgs args)
			{
				var result = await client.CallApiAsync<DCPagedCollection<DCAssetTypeItem>>("AssetTypeApi/Search", args);
				return result.Data;
			}

			public async Task<DCPagedLookupSet> SearchLookup(DCAssetTypeSearchArgs args)
			{
				var result = await client.CallApiAsync<DCPagedLookupSet>("AssetTypeApi/SearchLookup", args);
				return result.Data;
			}
		}

		public class InboxApi : BaseOriginationApi
		{
			internal InboxApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCInboxViewList> GetViews(DCInboxGetViewsArgs args)
			{
				var result = await client.CallApiAsync<DCInboxViewList>("InboxApi/GetViews", args);
				return result.Data;
			}

			public async Task<DCPagedCollection<DCInboxDataItem>> Search(DCInboxSearchArgs args, CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCPagedCollection<DCInboxDataItem>>("InboxApi/Search", args, ct: ct);
				return result.Data;
			}
		}

		public class CollectionsApi : BaseOriginationApi
		{
			public CollectionsApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<CollectionsProxy> Get(DCCollectionsGetArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCCollectionsDetails>("CollectionsApi/Get", args, ct: ct);
				return new CollectionsProxy(client, result.Data, result.Lookups);
			}

			public async Task<List<CollectionsProxy>> Search(DCCollectionsSearchArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = new List<CollectionsProxy>();
				var tasks = await client.CallApiAsync<DCCollection<DCCollectionsDetails>>("CollectionsApi/Search", args, ct: ct);

				foreach (DCCollectionsDetails task in tasks.Data)
					result.Add(new CollectionsProxy(client, task, tasks.Lookups));

				return result;
			}
		}

		public class ContractApi : BaseOriginationApi
		{
			internal ContractApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<IContractProxy<DCContract>> New(DCContractNewArgs args)
			{
				var result = await client.CallApiAsync<DCContract>("ContractApi/New", args);
				return ToContractProxy(result);
			}

			public async Task<IContractProxy<DCContract>> Get(int id, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCContract>("ContractApi/Get", new DCContractGetArgs {Id = id}, ct: ct);
				var resultProxy = ToContractProxy(result);
				ct.ThrowIfCancellationRequested();
				return resultProxy;
			}

			public async Task<IContractProxy<DCContract>> Save(DCContractSaveArgs args)
			{
				var result = await client.CallApiAsync<DCContract>("ContractApi/Save", args);
				return ToContractProxy(result);
			}

			protected IContractProxy<DCContract> ToContractProxy(ApiResponse<DCContract> result)
			{
				if (result.Data is DCContractLease)
					return new LeaseContractProxy(client, result.Data as DCContractLease, result.Lookups);
				if (result.Data is DCContractLoanAccount)
					return new LoanAccountContractProxy(client, result.Data as DCContractLoanAccount, result.Lookups);
				return new ContractProxy<DCContract>(client, result.Data, result.Lookups);
			}
		}

		public class AssetApi<TC> : BaseOriginationApi where TC : DCContract
		{
			public TC ContractData { get; }

			internal AssetApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task<AssetProxy<TC>> New(int assetTypeId)
			{
				var result = (await client.CallApiAsync<DCAsset>("AssetApi/New", new DCAssetNewArgs {Contract = ContractData, AssetTypeId = assetTypeId}));
				return new AssetProxy<TC>(client, ContractData, result.Data, result.Lookups);
			}

			public async Task<AssetProxy<TC>> Get(int id)
			{
				var result = (await client.CallApiAsync<DCAsset>("AssetApi/Get", new DCAssetGetArgs {ContractId = ContractData.GetId, Id = id}));
				return new AssetProxy<TC>(client, ContractData, result.Data, result.Lookups);
			}
		}

		public class AssetCustomFieldApi : BaseOriginationApi, ICustomFieldApi
		{
			public DCAsset AssetData { get; }
			public DCContract ContractData { get; }

			internal AssetCustomFieldApi(OriginationApiClient client, DCAsset assetData, DCContract contractData) : base(client)
			{
				AssetData = assetData;
				ContractData = contractData;
			}

			public async Task DeleteGroupRow(DCCustomFieldDeleteGroupRowArgs args)
			{
				args.ContextObjectId = AssetData.GetId;
				args.ParentContextObjectId = ContractData.GetId;
				await client.CallApiAsync<object>("AssetCustomFieldApi/DeleteGroupRow", args);
			}

			public async Task<DCCustomFieldDefinition> GetDefinition(DCCustomFieldGetDefinitionArgs args)
			{
				var result = await client.CallApiAsync<DCCustomFieldDefinition>("AssetCustomFieldApi/GetDefinition", args);
				return result.Data;
			}

			public async Task<DCLookupCollection> GetDbLookups(DCCustomFieldGetDbLookupsArgs args)
			{
				args.ContextObjectTypeId = AssetData.GetId;
				var result = await client.CallApiAsync<DCLookupCollection>("AssetCustomFieldApi/GetDbLookups", args);
				return result.Data;
			}

			public async Task<DCCustomFieldGroupRow> NewGroupRow(DCCustomFieldNewGroupRowArgs args)
			{
				args.ContextObjectId = AssetData.GetId;
				args.ParentContextObjectId = ContractData.GetId;
				var result = await client.CallApiAsync<DCCustomFieldGroupRow>("AssetCustomFieldApi/NewGroupRow", args);
				return result.Data;
			}

			public async Task<DCCollection<DCCustomFieldDefinition>> Search(DCCustomFieldSearchArgs args)
			{
				args.ContextObjectId = AssetData.GetId;
				var result = await client.CallApiAsync<DCCollection<DCCustomFieldDefinition>>("AssetCustomFieldApi/Search", args);
				return result.Data;
			}
		}

		public class AssetHdrCustomFieldApi : BaseOriginationApi, ICustomFieldApi
		{
			public DCContract ContractData { get; }

			internal AssetHdrCustomFieldApi(OriginationApiClient client, DCContract contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task DeleteGroupRow(DCCustomFieldDeleteGroupRowArgs args)
			{
				//args.ContextObjectId = AssetHdrData.Id;
				args.ParentContextObjectId = ContractData.GetId;
				await client.CallApiAsync<object>("AssetHdrCustomFieldApi/DeleteGroupRow", args);
			}

			public async Task<DCCustomFieldDefinition> GetDefinition(DCCustomFieldGetDefinitionArgs args)
			{
				var result = await client.CallApiAsync<DCCustomFieldDefinition>("AssetHdrCustomFieldApi/GetDefinition", args);
				return result.Data;
			}

			public async Task<DCLookupCollection> GetDbLookups(DCCustomFieldGetDbLookupsArgs args)
			{
				//args.ContextObjectTypeId = AssetHdrData.Id;
				var result = await client.CallApiAsync<DCLookupCollection>("AssetHdrCustomFieldApi/GetDbLookups", args);
				return result.Data;
			}

			public async Task<DCCustomFieldGroupRow> NewGroupRow(DCCustomFieldNewGroupRowArgs args)
			{
				//args.ContextObjectId = AssetHdrData.Id;
				args.ParentContextObjectId = ContractData.GetId;
				var result = await client.CallApiAsync<DCCustomFieldGroupRow>("AssetHdrCustomFieldApi/NewGroupRow", args);
				return result.Data;
			}

			public async Task<DCCollection<DCCustomFieldDefinition>> Search(DCCustomFieldSearchArgs args)
			{
				//args.ContextObjectId = AssetHdrData.Id;
				var result = await client.CallApiAsync<DCCollection<DCCustomFieldDefinition>>("AssetHdrCustomFieldApi/Search", args);
				return result.Data;
			}
		}

		public class PartyApi : BaseOriginationApi
		{
			public PartyApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<PartyProxy> New(DCPartyNewArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCParty>("PartyApi/New", args, ct: ct);
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task<PartyProxy> SetBusinessIndividual(DCPartySetBusinessIndividualArgs args)
			{
				var result = await client.CallApiAsync<DCParty>("PartyApi/SetBusinessIndividual", args);
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task<PartyProxy> Get(int partyNo)
			{
				var result = await client.CallApiAsync<DCParty>("PartyApi/Get", new DCPartyGetArgs {PartyNo = partyNo});
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task<PartyProxy> GetById(int id)
			{
				var result = await client.CallApiAsync<DCParty>("PartyApi/GetById", new DCPartyGetByIdArgs {Id = id});
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task<DCInboxViewList> GetSearchViews()
			{
				var result = await client.CallApiAsync<DCInboxViewList>("PartySearchApi/GetViews");
				return result.Data;
			}

			public async Task<DCPagedCollection<DCPartyItem>> Search(DCPartySearchViewDefinition args, CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCPagedCollection<DCPartyItem>>("PartySearchApi/Search", args, ct: ct);
				return result.Data;
			}
		}

		public class ContractCustomFieldApi<TC> : BaseOriginationApi, ICustomFieldApi where TC : DCContract
		{
			public TC ContractData { get; }

			internal ContractCustomFieldApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task DeleteGroupRow(DCCustomFieldDeleteGroupRowArgs args)
			{
				args.ContextObjectId = ContractData.GetId;
				await client.CallApiAsync<object>("ContractCustomFieldApi/DeleteGroupRow", args);
			}

			public async Task<DCCustomFieldDefinition> GetDefinition(DCCustomFieldGetDefinitionArgs args)
			{
				var result = await client.CallApiAsync<DCCustomFieldDefinition>("ContractCustomFieldApi/GetDefinition", args);
				return result.Data;
			}

			public async Task<DCLookupCollection> GetDbLookups(DCCustomFieldGetDbLookupsArgs args)
			{
				args.ContextObjectTypeId = ContractData.GetId;
				var result = await client.CallApiAsync<DCLookupCollection>("ContractCustomFieldApi/GetDbLookups", args);
				return result.Data;
			}

			public async Task<DCCustomFieldGroupRow> NewGroupRow(DCCustomFieldNewGroupRowArgs args)
			{
				args.ContextObjectId = ContractData.GetId;
				var result = await client.CallApiAsync<DCCustomFieldGroupRow>("ContractCustomFieldApi/NewGroupRow", args);
				return result.Data;
			}

			public async Task<DCCollection<DCCustomFieldDefinition>> Search(DCCustomFieldSearchArgs args)
			{
				args.ContextObjectId = ContractData.GetId;
				var result = await client.CallApiAsync<DCCollection<DCCustomFieldDefinition>>("ContractCustomFieldApi/Search", args);
				return result.Data;
			}
		}

		public class ContractPartyApi<TC> : BaseOriginationApi where TC : DCContract
		{
			public TC ContractData { get; private set; }

			internal ContractPartyApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task<PartyProxy> Get(DCContractPartyGetArgs args)
			{
				args.Id = args.Id <= GlobalConsts.NONE_ID ? ContractData.Id : args.Id;
				var result = await client.CallApiAsync<DCParty>("ContractPartyApi/Get", args);
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task<ContractPartyProxy<TC>> New(DCContractPartyNewArgs args)
			{
				args.Id = args.Id <= GlobalConsts.NONE_ID ? ContractData.Id : args.Id;
				var result = await client.CallApiAsync<DCContractParty>("ContractPartyApi/New", args);
				return new ContractPartyProxy<TC>(client, ContractData, result.Data);
			}

			public async Task<DCContractPartyList> Search(DCContractPartySearchArgs args, CancellationToken ct = default(CancellationToken))
			{
				args.ContractId = args.ContractId <= GlobalConsts.NONE_ID ? ContractData.GetId : args.ContractId;
				args.BusinessModelId = args.BusinessModelId <= GlobalConsts.NONE_ID ? ContractData.BusinessModelId : args.BusinessModelId;
				var result = await client.CallApiAsync<DCContractPartyList>("ContractPartyApi/Search", args, ct: ct);
				return result.Data;
			}

			public async Task<ContractPartyProxy<TC>> Set(DCContractParty args)
			{
				var result = await client.CallApiAsync<DCContractParty>(
					"ContractPartyApi/Set", new DCContractPartySetArgs
					{
						ContractParty = args,
						Id = ContractData.Id
					});
				return new ContractPartyProxy<TC>(client, ContractData, result.Data);
			}

			public async Task<PartyProxy> SaveCustomer(DCContractPartySaveCustomerArgs args)
			{
				args.Id = args.Id <= GlobalConsts.NONE_ID ? ContractData.Id : args.Id;
				var result = await client.CallApiAsync<DCParty>("ContractPartyApi/SaveCustomer", args);
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task Save(DCCollection<DCContractParty> items)
			{
				var result = await client.CallApiAsync<TC>("ContractPartyApi/Save", new DCContractPartySaveArgs {Contract = ContractData, ContractParties = items});
				ContractData = result.Data;
			}
		}

		public class ContractWorkflowTodoApi<TC> : BaseOriginationApi where TC : DCContract
		{
			public TC ContractData { get; }

			internal ContractWorkflowTodoApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task<DCContractTodoList> Search(DCContractTodoSearchArgs args)
			{
				args.ContractId = args.ContractId <= GlobalConsts.NONE_ID ? ContractData.GetId : args.ContractId;
				var result = await client.CallApiAsync<DCContractTodoList>("ContractWorkflowTodoApi/Search", args);
				return result.Data;
			}

			public async Task Save(DCCollection<DCTodoItem> items)
			{
				await client.CallApiAsync<object>("ContractWorkflowTodoApi/Save", new DCContractTodoSaveArgs {ContractId = ContractData.GetId, Items = items});
			}
		}

		public class FlowsApi<TC> : BaseOriginationApi where TC : DCContract
		{
			public TC ContractData { get; }

			internal FlowsApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task<DCPagedCollection<DCFlowItem>> Search(DCContractFlowsSearchArgs args)
			{
				args.ContractId = ContractData.GetId;
				var result = await client.CallApiAsync<DCPagedCollection<DCFlowItem>>("ContractFlowsApi/Search", args);
				return result.Data;
			}
		}

		public class TerminationApi<TC> : BaseOriginationApi where TC : DCContract
		{
			public TC ContractData { get; }

			internal TerminationApi(OriginationApiClient client, TC contractData) : base(client)
			{
				ContractData = contractData;
			}

			public async Task<DCTerminationQuote> Save(DCTerminationSaveArgs args)
			{
				args.Id = ContractData.Id;
				var result = await client.CallApiAsync<DCTerminationQuote>("TerminationApi/Save", args);
				return result.Data;
			}
		}

		public class DataUploadApi : BaseOriginationApi
		{
			public DataUploadApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCContractUploadResult> UploadContract(DCContractUploadArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCContractUploadResult>("DataUploadApi/UploadContract", args, ct: ct);
				return result.Data;
			}

			public async Task<DCCollectionTaskUploadResult> UploadTask(DCCollectionTaskUploadArgs args, CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCCollectionTaskUploadResult>("DataUploadApi/UploadCollectionTask", args, ct: ct);
				return result.Data;
			}
		}

		public class DocumentApi : BaseOriginationApi
		{
			public DocumentApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCPagedCollection<DCDocMetadataItem>> Search(DCDocumentSearchArgs args, CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCPagedCollection<DCDocMetadataItem>>("DocumentApi/Search", args, ct: ct);
				return result.Data;
			}

			public async Task<DCInboxViewList> GetView()
			{
				var result = await client.CallApiAsync<DCInboxViewList>("DocumentApi/GetView");
				return result.Data;
			}

			public async Task Delete(DCDocumentDeleteArgs args)
			{
				await client.CallApiAsync<object>("DocumentApi/Delete", args);
			}

			public async Task ValidateDownload(DCDocumentValidateDownloadArgs args)
			{
				await client.CallApiAsync<object>("DocumentApi/ValidateDownload", args);
			}

			public async Task<FileInfoModel> Download(
				DCDocumentDownloadArgs args,
				Action<LoadProgressChangedEventArgs> progress = null,
				CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<FileInfoModel>("DocumentApi/Download", args, responseProgress: progress, ct: ct);
				return result.Data;
			}

			public async Task<int> Upload(
				DCDocumentUploadArgs args, string fileName, byte[] data,
				Action<LoadProgressChangedEventArgs> progress = null,
				CancellationToken ct = default(CancellationToken))
			{
				var form = new MultipartFormDataContent
				{
					{new StringContent(args.Name), nameof(args.Name)},
					{new StringContent(args.DocCategoryId.ToString()), nameof(args.DocCategoryId)},
					{new StringContent(args.SecurityClassification.ToString()), nameof(args.SecurityClassification)},
					{new StringContent(args.Description), nameof(args.Description)},
					{new StringContent(args.ContextObjectId.ToString()), nameof(args.ContextObjectId)},
					{new StringContent(args.DocLinkType.ToString()), nameof(args.DocLinkType)},
					{new ByteArrayContent(data, 0, data.Length), "document", fileName}
				};

				ApiResponse<object> result = await client.CallApiAsync<object>(
					"DocumentApi/Upload", null,
					progress == null ? (HttpContent)form : new ProgressDataContent(form, progress, fileName), ct: ct);

				// Because DocumentApi/Upload returns an int, not a DC we need to do the magic below
				if (result.Data == null)
					return GlobalConsts.NONE_ID;
				if (!Int64.TryParse(result.Data.ToString(), out long docMetadataId))
					throw new Exception(
						string.Format(
							MobileResourceHelper.GetViewResource("UnknownErrorOccurred"),
							string.Format(MobileResourceHelper.GetViewResource("ApiDocUploadResponseParseError"), result.Data)));

				return Convert.ToInt32(docMetadataId);
			}

			public async Task<IDictionary<string, DCLookupCollection>> GetLookups(CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<object>("DocumentApi/GetLookups", ct: ct);
				return result.Lookups;
			}

			public async Task<GlobalEnums.DocNoteSecurityClassification> GetSecurityClassification(DCDocumentGetSecurityClassificationArgs args)
			{
				var result = await client.CallApiAsync<GlobalEnums.DocNoteSecurityClassification>("DocumentApi/GetSecurityClassification");
				return result.Data;
			}

			public async Task<string> GetExternalViewerUrl(DCDocumentGetExternalViewerUrlArgs args)
			{
				var result = await client.CallApiAsync<string>("DocumentApi/GetExternalViewerUrl");
				return result.Data;
			}

			public async Task Refresh(DCDocumentRefreshArgs args)
			{
				await client.CallApiAsync<object>("DocumentApi/Refresh");
			}

			public async Task<bool> IsValidExternalStoreRegistered(DCDocumentIsValidExternalStoreRegisteredArgs args)
			{
				var result = await client.CallApiAsync<bool>("DocumentApi/IsValidExternalStoreRegistered");
				return result.Data;
			}
		}

		public class GlobalizationApi : BaseOriginationApi
		{
			public GlobalizationApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task SetCulture(string cultureName)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCCultureSetArgs>();
				args.CultureName = cultureName;
				await client.CallApiAsync<object>("GlobalizationApi/SetCulture", args);
			}
		}

		public class LocationApi : BaseOriginationApi
		{
			public LocationApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCLookupCollection> SearchLookup(DCLocationSearchArgs args)
			{
				var result = await client.CallApiAsync<DCLookupCollection>("LocationApi/SearchLookup", args);
				return result.Data;
			}

			public async Task<DCPagedCollection<DCLocation>> Search(DCLocationSearchArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCPagedCollection<DCLocation>>("LocationApi/Search", args, ct: ct);
				return result.Data;
			}

			public async Task<DCLocation> Get(DCLocationGetArgs args)
			{
				var result = await client.CallApiAsync<DCLocation>("LocationApi/Get", args);
				return result.Data;
			}

			public async Task<DCLocation> GetOwner(DCLocationGetOwnerArgs args)
			{
				var result = await client.CallApiAsync<DCLocation>("LocationApi/GetOwner", args);
				return result.Data;
			}

			public async Task<DCLookupCollection> GetOwnerByType(DCLocationGetOwnerByTypeArgs args)
			{
				var result = await client.CallApiAsync<DCLookupCollection>("LocationApi/GetOwnerByType", args);
				return result.Data;
			}
		}

		public class LookupSetApi : BaseOriginationApi
		{
			public LookupSetApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<IDictionary<string, DCLookupCollection>> Search(DCLookupSetSearchArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<IDictionary<string, DCLookupCollection>>("LookupSetApi/Search", args, ct: ct);
				return result.Lookups;
			}

			public async Task<IDictionary<string, DCLookupCollection>> SearchXt(DCLookupSetSearchArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<IDictionary<string, DCLookupCollection>>("LookupSetApi/SearchXt", args, ct: ct);
				return result.Lookups;
			}
		}

		public class NoteApi : BaseOriginationApi
		{
			public NoteApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<NoteProxy> New(DCNoteNewArgs args)
			{
				var result = await client.CallApiAsync<DCNote>("NoteApi/New", args);
				return new NoteProxy(client, result.Data, result.Lookups);
			}

			public async Task<NoteProxy> Get(DCNoteGetArgs args)
			{
				var result = await client.CallApiAsync<DCNote>("NoteApi/Get", args);
				return new NoteProxy(client, result.Data, result.Lookups);
			}
		}

		public class PartyAddressApi : BaseOriginationApi
		{
			public DCParty PartyData { get; }

			internal PartyAddressApi(OriginationApiClient client, DCParty partyData) : base(client)
			{
				PartyData = partyData;
			}

			public async Task<DCPartyAddress> New()
			{
				var result = await client.CallApiAsync<DCPartyAddress>("PartyAddressApi/New", new DCPartyAddressNewArgs {PartyId = PartyData.GetId});
				return result.Data;
			}

			public async Task<DCCollection<DCPartyAddress>> Search()
			{
				var result = await client.CallApiAsync<DCCollection<DCPartyAddress>>("PartyAddressApi/Search", new DCPartyAddressSearchArgs {PartyId = PartyData.GetId});
				return result.Data;
			}
		}

		public class PartyContactApi : BaseOriginationApi
		{
			public DCParty PartyData { get; }

			internal PartyContactApi(OriginationApiClient client, DCParty partyData) : base(client)
			{
				PartyData = partyData;
			}

			public async Task<PartyContactProxy> New(DCPartyContactNewArgs args)
			{
				args.PartyId = PartyData.GetId;
				var result = await client.CallApiAsync<DCPartyContact>("PartyContactApi/New", args);
				return new PartyContactProxy(client, PartyData, result.Data, result.Lookups);
			}

			public async Task<PartyContactProxy> Get(int partyContactId)
			{
				var result = await client.CallApiAsync<DCPartyContact>("PartyContactApi/Get", new DCPartyContactGetArgs {PartyId = PartyData.GetId, Id = partyContactId});
				return new PartyContactProxy(client, PartyData, result.Data, result.Lookups);
			}

			public async Task<DCPagedCollection<DCPartyContactItem>> Search(DCPartyContactSearchArgs args)
			{
				args.PartyId = PartyData.GetId;
				var result = await client.CallApiAsync<DCPagedCollection<DCPartyContactItem>>("PartyContactApi/Search", args);
				return result.Data;
			}
		}

		public class PartyCustomFieldApi : BaseOriginationApi, ICustomFieldApi
		{
			public DCParty PartyData { get; }

			internal PartyCustomFieldApi(OriginationApiClient client, DCParty partyData) : base(client)
			{
				PartyData = partyData;
			}

			public async Task DeleteGroupRow(DCCustomFieldDeleteGroupRowArgs args)
			{
				args.ContextObjectId = PartyData.GetId;
				await client.CallApiAsync<object>("PartyCustomFieldApi/DeleteGroupRow", args);
			}

			public async Task<DCCustomFieldDefinition> GetDefinition(DCCustomFieldGetDefinitionArgs args)
			{
				var result = await client.CallApiAsync<DCCustomFieldDefinition>("PartyCustomFieldApi/GetDefinition", args);
				return result.Data;
			}

			public async Task<DCLookupCollection> GetDbLookups(DCCustomFieldGetDbLookupsArgs args)
			{
				args.ContextObjectTypeId = PartyData.GetId;
				var result = await client.CallApiAsync<DCLookupCollection>("PartyCustomFieldApi/GetDbLookups", args);
				return result.Data;
			}

			public async Task<DCCustomFieldGroupRow> NewGroupRow(DCCustomFieldNewGroupRowArgs args)
			{
				args.ContextObjectId = PartyData.GetId;
				var result = await client.CallApiAsync<DCCustomFieldGroupRow>("PartyCustomFieldApi/NewGroupRow", args);
				return result.Data;
			}

			public async Task<DCCollection<DCCustomFieldDefinition>> Search(DCCustomFieldSearchArgs args)
			{
				args.ContextObjectId = PartyData.GetId;
				var result = await client.CallApiAsync<DCCollection<DCCustomFieldDefinition>>("PartyCustomFieldApi/Search", args);
				return result.Data;
			}
		}

		public class PrintApi : BaseOriginationApi
		{
			public PrintApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCCollection<DCDocRule>> SearchDocRules(DCPrintSearchDocRulesArgs args)
			{
				var result = await client.CallApiAsync<DCCollection<DCDocRule>>("PrintApi/SearchDocRules", args);
				return result.Data;
			}

			public async Task<DCCollection<int>> Print(DCPrintArgs args)
			{
				var result = (await client.CallApiAsync<DCCollection<int>>("PrintApi/Print", args)).Data;
				return result;
			}

			public async Task Download(DCPrintDownloadArgs args)
			{
				await client.CallApiAsync<object>("PrintApi/Download", args);
			}
		}

		public class ReceiptProcessingApi : BaseOriginationApi
		{
			public ReceiptProcessingApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<ReceiptProcessingProxy> New(CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/New", ct: ct);
				return new ReceiptProcessingProxy(client, result.Data, result.Lookups);
			}

			public async Task<ReceiptProcessingProxy> Get(int bankFlowId)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingGetArgs>();
				args.BankFlowId = bankFlowId;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/Get", args);
				return new ReceiptProcessingProxy(client, result.Data, result.Lookups);
			}
		}

		public class SettlementBankInfoApi : BaseOriginationApi
		{
			public DCParty PartyData { get; private set; }

			internal SettlementBankInfoApi(OriginationApiClient client, DCParty partyData) : base(client)
			{
				PartyData = partyData;
			}

			public async Task<SettlementBankInfoProxy> New()
			{
				var result = await client.CallApiAsync<DCSettlementBankInfo>("SettlementBankInfoApi/New", new DCSettlementBankInfoNewArgs {PartyId = PartyData.GetId});
				return new SettlementBankInfoProxy(client, PartyData, result.Data, result.Lookups);
			}

			public async Task<SettlementBankInfoProxy> Get(int settlementBankInfoId)
			{
				var result = await client.CallApiAsync<DCSettlementBankInfo>("SettlementBankInfoApi/Get", new DCSettlementBankInfoGetArgs {PartyId = PartyData.GetId, Id = settlementBankInfoId});
				return new SettlementBankInfoProxy(client, PartyData, result.Data, result.Lookups);
			}

			public async Task<DCPagedCollection<DCSettlementBankInfoItem>> Search(DCSettlementBankInfoSearchArgs args)
			{
				args.PartyId = PartyData.GetId;
				var result = await client.CallApiAsync<DCPagedCollection<DCSettlementBankInfoItem>>("SettlementBankInfoApi/Search", args);
				return result.Data;
			}
		}

		public class StatelessCalcApi : BaseOriginationApi
		{
			public StatelessCalcApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCSlContract> Calculate(DCSlContractCalculateArgs data, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCSlContract>("StatelessApi/ContractSlApi/Calculate", data, ct: ct);
				return result.Data;
			}

			public async Task<DCSlContractSaveResult> Save(DCSlContractSaveArgs data)
			{
				var result = await client.CallApiAsync<DCSlContractSaveResult>("StatelessApi/ContractSlApi/Save", data);
				return result.Data;
			}
		}

		public class SystemApi : BaseOriginationApi
		{
			public SystemApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DateTime> GetSystemDate()
			{
				var result = await client.CallApiAsync<DateTime>("SystemApi/GetSystemDate");
				return result.Data;
			}

			public async Task<DCClientConfiguration> GetConfiguration(CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCClientConfiguration>("SystemApi/GetConfiguration", ct: ct);
				return result.Data;
			}
		}

		public class TaskApi : BaseOriginationApi
		{
			public TaskApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<TaskProxy> New()
			{
				var result = await client.CallApiAsync<DCTask>("TaskApi/New");
				return new TaskProxy(client, result.Data, result.Lookups);
			}

			public async Task<TaskProxy> Get(int taskId)
			{
				var result = await client.CallApiAsync<DCTask>("TaskApi/Get", new DCTaskGetArgs {Id = taskId});
				return new TaskProxy(client, result.Data, result.Lookups);
			}
		}

		public class UserApi : BaseOriginationApi
		{
			public UserApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCLookupCollection> Search(DCUserSearchArgs args)
			{
				var result = await client.CallApiAsync<DCLookupCollection>("UserApi/Search", args);
				return result.Data;
			}
		}

		public class WorkflowApi : BaseOriginationApi
		{
			public WorkflowApi(OriginationApiClient client) : base(client)
			{
			}

			public async Task<DCWorkflow> GetSummaries(DCWorkflowSummaryArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCWorkflow>("WorkflowApi/GetSummaries", args, ct: ct);
				return result.Data;
			}

			public async Task<DCWorkflowItem> GetDetail(DCWorkflowSummaryArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCWorkflowItem>("WorkflowApi/GetDetail", args, ct: ct);
				return result.Data;
			}

			public async Task<DCWorkflowContextChangedData> SetState(DCWorkflowSummaryArgs args, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCWorkflowContextChangedData>("WorkflowApi/SetState", args, ct: ct);
				return result.Data;
			}
		}

		#endregion API Definitions

		#region Proxies

		public abstract class BaseProxy<T> : IDataProxy<T> where T : DCBase
		{
			protected readonly OriginationApiClient client;

			internal BaseProxy(OriginationApiClient client, T data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				Lookups = lookups;
				Data = data;
				this.client = client;
			}

			public T Data { get; protected set; }
			public IDictionary<string, DCLookupCollection> Lookups { get; protected set; }
		}

		public class LeaseContractProxy : ContractProxy<DCContractLease>
		{
			public LeaseContractProxy(OriginationApiClient client, DCContractLease data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
			}
		}

		public class LoanAccountContractProxy : ContractProxy<DCContractLoanAccount>
		{
			public LoanAccountContractProxy(OriginationApiClient client, DCContractLoanAccount data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
			}
		}

		public class ContractProxy<T> : BaseProxy<DCContract>, IContractProxy<T> where T : DCContract
		{
			public ContractProxy(OriginationApiClient client, T data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
				SetContractData(data, Lookups);
			}

			public new T Data
			{
				get => base.Data as T;
				private set => base.Data = value;
			}

			public AssetApi<T> Asset { get; private set; }
			public AssetHdrCustomFieldApi AssetHdrCustomField { get; private set; }
			public ContractCustomFieldApi<T> CustomFields { get; private set; }
			public FlowsApi<T> Flows { get; private set; }
			public ContractPartyApi<T> Parties { get; private set; }
			public TerminationApi<T> Termination { get; private set; }
			public ContractWorkflowTodoApi<T> WorkflowTodo { get; private set; }

			public async Task Calculate(DCContractCalculateArgs args, CancellationToken ct = default(CancellationToken))
			{
				args.Contract = Data;
				var result = await client.CallApiAsync<T>("ContractApi/Calculate", args, ct: ct);
				SetContractData(result);
			}

			public async Task<DCContractCalculator> GetCalculator()
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCContractCalculatorGetArgs>();
				args.Id = Data.Id;
				args.AssetId = GlobalConsts.NONE_ID;
				args.CalculationMode = Data.CalculationMode;
				var result = await client.CallApiAsync<DCContractCalculator>("ContractDefaultingApi/GetCalculator", args);
				return result.Data;
			}

			public async Task<bool> Default(DCContractDefaultingArgs args)
			{
				args.ContractId = Data.GetId;
				args.Contract = Data;
				var result = await client.CallApiAsync<T>("ContractDefaultingApi/Default", args);
				if (result?.Data != null)
				{
					SetContractData(result);
					return true;
				}

				return result?.Data != null;
			}

			public async Task<bool> Save(DCContractSaveArgs args, CancellationToken ct = default(CancellationToken))
			{
				args.Contract = Data;
				var result = await client.CallApiAsync<T>("ContractApi/Save", args, ct: ct);
				SetContractData(result);
				return result?.Data != null;
			}

			public async Task SetCustomer(int partyId)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCContractSetCustomerArgs>();
				args.Contract = Data;
				args.PartyId = partyId;
				var result = await client.CallApiAsync<T>("ContractApi/SetCustomer", args);
				SetContractData(result);
			}

			public async Task SetBroker(int partyId)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCContractSetCustomerArgs>();
				args.Contract = Data;
				args.PartyId = partyId;
				var result = await client.CallApiAsync<T>("ContractApi/SetBroker", args);
				SetContractData(result);
			}

			public async Task SetInstallments(int installments)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCContractSetInstallmentsArgs>();
				args.Installments = installments;
				args.Contract = Data;
				var result = await client.CallApiAsync<T>("ContractApi/SetInstallments", args);
				SetContractData(result);
			}

			public async Task SetInstallmentFrequency(GlobalEnums.InstallmentFrequency frequency)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCContractSetInstallmentFrequencyArgs>();
				args.InstallmentFrequency = frequency;
				args.Contract = Data;
				var result = await client.CallApiAsync<T>("ContractApi/SetInstallmentFrequency", args);
				SetContractData(result);
			}

			private void SetContractData(ApiResponse<T> result)
			{
				SetContractData(result.Data, result.Lookups);
			}

			private void SetContractData(T data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				Data = data ?? Data;
				Lookups = lookups ?? Lookups;
				Asset = new AssetApi<T>(client, data);
				CustomFields = new ContractCustomFieldApi<T>(client, data);
				AssetHdrCustomField = new AssetHdrCustomFieldApi(client, data);
				Flows = new FlowsApi<T>(client, data);
				Parties = new ContractPartyApi<T>(client, data);
				Termination = new TerminationApi<T>(client, data);
				WorkflowTodo = new ContractWorkflowTodoApi<T>(client, data);
			}
		}

		public class CollectionsProxy : BaseProxy<DCCollectionsDetails>
		{
			public CollectionsProxy(OriginationApiClient client, DCCollectionsDetails data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
			}
		}

		public class AssetProxy<TC> : BaseProxy<DCAsset> where TC : DCContract
		{
			public AssetProxy(OriginationApiClient client, TC contractData, DCAsset data, IDictionary<string, DCLookupCollection> lookups) : base(client, data, lookups)
			{
				ContractData = contractData;
				SetAssetData(data, lookups);
			}

			public TC ContractData { get; }
			public AssetCustomFieldApi CustomFields { get; private set; }

			public async Task<DCAssetUpdate> Update(CancellationToken ct = default(CancellationToken))
			{
				var result = (await client.CallApiAsync<DCAssetUpdate>("AssetApi/Update", new DCAssetUpdateArgs {Contract = ContractData, Asset = Data}, ct: ct)).Data;
				SetAssetData(result?.Asset);
				return result;
			}

			public async Task<bool> Default(GlobalEnums.DefaultingChange change = GlobalEnums.DefaultingChange.AssetViaAssetType)
			{
				var result = await client.CallApiAsync<DCAsset>(
					"ContractDefaultingApi/DefaultAsset", new DCAssetDefaultingArgs
					{
						ContractId = ContractData.GetId,
						Asset = Data,
						DefaultingChange = change
					});

				SetAssetData(result?.Data, result?.Lookups);
				return result != null;
			}

			private void SetAssetData(DCAsset data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				Data = data ?? Data;
				Lookups = lookups ?? Lookups;
				CustomFields = new AssetCustomFieldApi(client, data, ContractData);
			}
		}

		public class ContractPartyProxy<TC> : BaseProxy<DCContractParty> where TC : DCContract
		{
			public ContractPartyProxy(OriginationApiClient client, TC contractData, DCContractParty data) : base(client, data)
			{
				ContractData = contractData;
			}

			public TC ContractData { get; }

			public async Task<PartyProxy> Update(DCContractPartyUpdateArgs args)
			{
				var result = await client.CallApiAsync<DCParty>("ContractPartyApi/Update", args);
				return new PartyProxy(client, result.Data, result.Lookups);
			}

			public async Task Set()
			{
				var result = await client.CallApiAsync<DCContractParty>(
					"ContractPartyApi/Set", new DCContractPartySetArgs
					{
						ContractParty = Data,
						Id = ContractData.Id
					});
				Data = result.Data;
			}

			public async Task Remove()
			{
				await client.CallApiAsync<object>(
					"ContractPartyApi/Remove", new DCContractPartyRemoveArgs
					{
						ContractParty = Data,
						Id = ContractData.Id
					});
				Data = null;
			}
		}

		public class NoteProxy : BaseProxy<DCNote>
		{
			public NoteProxy(OriginationApiClient client, DCNote data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
			}

			public async Task Save(CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCNote>("NoteApi/Save", new DCNoteSaveArgs {Note = Data}, ct: ct);
				Data = result.Data;
			}
		}

		public class PartyProxy : BaseProxy<DCParty>
		{
			public PartyAddressApi Address { get; private set; }
			public PartyContactApi Contact { get; private set; }
			public PartyCustomFieldApi CustomFields { get; private set; }
			public SettlementBankInfoApi SettlementBankInfo { get; private set; }

			public PartyProxy(OriginationApiClient client, DCParty data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
				SetPartyData(data, lookups);
			}

			public void Update(DCParty data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				SetPartyData(data, lookups);
			}

			public async Task Save(DCParty data = null, CancellationToken ct = default(CancellationToken))
			{
				var result = await client.CallApiAsync<DCParty>("PartyApi/Save", new DCPartySaveArgs {Party = data ?? Data}, ct: ct);
				SetPartyData(result.Data, result.Lookups);
			}

			public async Task SetBusinessIndividual(GlobalEnums.BusinessIndividual classification)
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCPartySetBusinessIndividualArgs>();
				args.BusinessIndividual = classification;
				args.Party = Data;
				var result = await client.CallApiAsync<DCParty>("PartyApi/SetBusinessIndividual", args);

				SetPartyData(result.Data, result.Lookups);
			}

			private void SetPartyData(DCParty data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				Data = data ?? Data;
				Lookups = lookups == null && Lookups != null ? Lookups : lookups;
				Address = new PartyAddressApi(client, Data);
				Contact = new PartyContactApi(client, Data);
				CustomFields = new PartyCustomFieldApi(client, data);
				SettlementBankInfo = new SettlementBankInfoApi(client, Data);
			}
		}

		public class PartyContactProxy : BaseProxy<DCPartyContact>
		{
			public DCParty PartyData { get; private set; }

			public PartyContactProxy(OriginationApiClient client, DCParty partyData, DCPartyContact data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
				PartyData = partyData;
			}

			public async Task Update(CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCParty>("PartyContactApi/Update", new DCPartyContactUpdateArgs {Party = PartyData, PartyContact = Data}, ct: ct);
				PartyData = result.Data;
			}

			public async Task Remove(CancellationToken ct)
			{
				var result = await client.CallApiAsync<DCParty>("PartyContactApi/Remove", new DCPartyContactRemoveArgs {Party = PartyData, Id = Data.Id}, ct: ct);
				PartyData = result.Data;
			}
		}

		public class ReceiptProcessingProxy : BaseProxy<DCReceiptProcessing>
		{
			public ReceiptProcessingProxy(OriginationApiClient client, DCReceiptProcessing data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
				SetReceiptData(data, lookups);
			}

			public async Task Default(DCReceiptProcessing data, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingDefaultArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/Default", args, ct: ct);
				SetReceiptData(result.Data, result.Lookups);
			}

			public async Task Save(DCReceiptProcessing data = null, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingSaveArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/Save", args, ct: ct);
				SetReceiptData(result.Data, result.Lookups);
			}

			public async Task GetLookups(DCReceiptProcessing data = null, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingGetLookupsArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/GetLookups", ct: ct);

				SetReceiptData(result.Data, result.Lookups);
			}

			public async Task SetSettlementBankInfo(DCReceiptProcessing data = null, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingSetSettlementBankInfoArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/SetSettlementBankInfo", args, ct: ct);
				SetReceiptData(result.Data, result.Lookups);
			}

			public async Task GetAllocations(DCReceiptProcessing data = null, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingGetAllocationsArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/GetAllocations", args, ct: ct);
				SetReceiptData(result.Data, result.Lookups);
			}

			public async Task SaveAllocations(DCReceiptProcessing data = null, CancellationToken ct = default(CancellationToken))
			{
				var args = DependencyManager.Current.ResolveOrThrow<DCReceiptProcessingSaveAllocationsArgs>();
				args.ReceiptProcessing = data ?? Data;

				var result = await client.CallApiAsync<DCReceiptProcessing>("ReceiptProcessingApi/SaveAllocations", args, ct: ct);
				SetReceiptData(result.Data, result.Lookups);
			}

			private void SetReceiptData(DCReceiptProcessing data, IDictionary<string, DCLookupCollection> lookups = null)
			{
				Data = data ?? Data;
				Lookups = lookups == null && Lookups != null ? Lookups : lookups;
			}
		}

		public class SettlementBankInfoProxy : BaseProxy<DCSettlementBankInfo>
		{
			public DCParty PartyData { get; private set; }

			public SettlementBankInfoProxy(OriginationApiClient client, DCParty partyData, DCSettlementBankInfo data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
				PartyData = partyData;
			}

			public async Task Update()
			{
				var result = await client.CallApiAsync<DCParty>("SettlementBankInfoApi/Update", new DCSettlementBankInfoUpdateArgs {Party = PartyData, SettlementBankInfo = Data});

				PartyData = result.Data;
			}
		}

		public class TaskProxy : BaseProxy<DCTask>
		{
			public TaskProxy(OriginationApiClient client, DCTask data, IDictionary<string, DCLookupCollection> lookups = null) : base(client, data, lookups)
			{
			}

			public async Task Save()
			{
				var result = await client.CallApiAsync<DCTask>("TaskApi/Save", new DCTaskSaveArgs {Task = Data});
				Data = result.Data;
			}
		}

		#endregion Proxies
	}

	public sealed class ApiJsonContent : HttpContent
	{
		private readonly object serializationTarget;
		private static readonly JsonNetSerializerOrigination serializer = new JsonNetSerializerOrigination();
		private const string uuidHeader = "Uuid";

		public ApiJsonContent(object serializationTarget)
		{
			this.serializationTarget = serializationTarget;
			Headers.ContentType = new MediaTypeHeaderValue("application/json");
			Headers.Add(uuidHeader, Guid.NewGuid().ToString("D"));
		}

		protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
		{
			if (serializationTarget == null)
				return;

			string requestString = serializer.Serialize(serializationTarget);
			byte[] requestBytes = Encoding.UTF8.GetBytes(requestString);
			await stream.WriteAsync(requestBytes, 0, requestBytes.Length);
		}

		protected override bool TryComputeLength(out long length)
		{
			length = -1L;
			return false;
		}
	}

	public sealed class ProgressDataContent : HttpContent
	{
		private const int defaultBufferSize = 8 * 4096;
		private const string uuidHeader = "Uuid";

		private readonly HttpContent content;
		private readonly int bufferSize;
		private readonly Action<LoadProgressChangedEventArgs> progress;
		private readonly string description;

		public ProgressDataContent(HttpContent content, Action<LoadProgressChangedEventArgs> progress, string description)
			: this(content, defaultBufferSize, progress, description)
		{
		}

		public ProgressDataContent(HttpContent content, int bufferSize, Action<LoadProgressChangedEventArgs> progress, string description)
		{
			if (content == null)
				throw new ArgumentNullException(nameof(content));

			if (progress == null)
				throw new ArgumentNullException(nameof(progress));

			if (bufferSize <= 0)
				bufferSize = defaultBufferSize;

			this.content = content;
			this.bufferSize = bufferSize;
			this.progress = progress;
			this.description = description;

			content.Headers.ForEach(header => Headers.Add(header.Key, header.Value));
			Headers.Add(uuidHeader, Guid.NewGuid().ToString("D"));
		}

		protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
		{
			var buffer = new byte[bufferSize];
			TryComputeLength(out long size);
			var uploaded = 0;

			using (var sinput = await content.ReadAsStreamAsync())
			{
				while (true)
				{
					var length = sinput.Read(buffer, 0, buffer.Length);
					if (length <= 0) break;

					uploaded += length;
					var percent = (int)(100.0 * uploaded / size);
					progress(new LoadProgressChangedEventArgs(false, description, percent, uploaded, size));

					stream.Write(buffer, 0, length);
					stream.Flush();
				}
			}

			stream.Flush();
		}

		protected override bool TryComputeLength(out long length)
		{
			length = content.Headers.ContentLength.GetValueOrDefault();
			return true;
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
				content.Dispose();

			base.Dispose(disposing);
		}

		public void Complete()
		{
			TryComputeLength(out long size);
			progress(
				new LoadProgressChangedEventArgs(false, description, 100, size, size)
				{
					IsCompleted = true
				});
		}
	}

	internal static class HttpClientExtensions
	{
		internal static bool IsJsonResponse(this HttpResponseMessage response)
		{
			return response?.Content?.Headers?.ContentType?.MediaType == "application/json";
		}

		internal static bool IsHtmlResponse(this HttpResponseMessage response)
		{
			return response?.Content?.Headers?.ContentType?.MediaType == "text/html";
		}

		internal static bool IsFileDownloadResponse(this HttpResponseMessage response)
		{
			return response?.Content?.Headers?.ContentDisposition != null ||
			       response?.Content?.Headers?.ContentType?.MediaType == "application/download";
		}
	}

	#region Message Handlers

	public class LoggingHandler : DelegatingHandler
	{
		private readonly Uri baseUri;

		public LoggingHandler(Uri baseUri) : this(baseUri, DependencyManager.Current.ResolveOrThrow<HttpClientHandler>())
		{
		}

		public LoggingHandler(Uri baseUri, HttpClientHandler inner) : base(inner)
		{
			this.baseUri = baseUri;
		}

		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			var sw = new Stopwatch();
			var sb = new StringBuilder();
			LogMessageType logLevel = AppCenterHelper.GetLogLevel();
			bool doLogBody = logLevel >= LogMessageType.Trace;

			string requestShortUrl = request.RequestUri.LocalPath.Replace(baseUri.LocalPath, string.Empty);
			string requestBody = !doLogBody || request.Content == null || request.Content is ProgressDataContent
				? string.Empty
				: await request.Content.ReadAsStringAsync() ?? string.Empty;

			sb.AppendFormat("Call {0}\t", requestShortUrl);

			// ReSharper disable once ConditionIsAlwaysTrueOrFalse
			if (doLogBody)
				LogHelper.Log(LogMessage.Create(LogMessageType.Trace, $"{request.Method} request to {request.RequestUri}\r\n{request}\r\n{requestBody}"));
			else
				LogHelper.LogInfo($"{request.Method} request to {request.RequestUri}");

			if (doLogBody && !string.IsNullOrWhiteSpace(requestBody))
			{
				try
				{
					LogHelper.Log(LogMessage.Create(LogMessageType.Trace, $"Formatted request body\r\n{JObject.Parse(requestBody)}"));
				}
				catch (Exception e)
				{
					LogHelper.LogError(e);
				}
			}

			HttpResponseMessage response = null;
			sw.Restart();
			try
			{
				response = await base.SendAsync(request, cancellationToken);
			}
			finally
			{
				sw.Stop();
				if (response != null)
				{
					string responseBody = (!doLogBody || response.Content == null ? string.Empty : await response.Content.ReadAsStringAsync()) ?? string.Empty;

					if (doLogBody)
						LogHelper.Log(LogMessage.Create(LogMessageType.Trace, $"Response from {request.RequestUri}\r\n{response}\r\n{responseBody}"));
					else
						LogHelper.LogInfo($"Response from {request.RequestUri}");

					bool isJsonResponse = !string.IsNullOrEmpty(responseBody) && response.IsJsonResponse();
					if (doLogBody && isJsonResponse)
					{
						try
						{
							LogHelper.Log(LogMessage.Create(LogMessageType.Trace, $"Formatted response body\r\n{JObject.Parse(responseBody)}"));
						}
						catch (Exception e)
						{
							LogHelper.LogError(e);
						}
					}

					int statusCode = (int)response.StatusCode;
					sb
						.AppendFormat("({0}) {1}", (int)response.StatusCode, response.ReasonPhrase)
						.AppendFormat(" ({0:mm\\:ss\\.fff} ms)", sw.Elapsed)
						.Append($" Req / Resp: {requestBody.Length} / {responseBody.Length} bytes");

					if (statusCode < 300)
						LogHelper.LogInfo(sb.ToString());
					else if (statusCode >= 300 && statusCode < 400)
						LogHelper.LogInfo(sb.ToString());
					else if (statusCode >= 400 && statusCode < 500)
						LogHelper.LogWarning(sb.ToString());
					else
						LogHelper.LogError(sb.ToString());

					if (statusCode >= 400)
					{
						if (!doLogBody && logLevel >= LogMessageType.Error)
						{
							if (!string.IsNullOrWhiteSpace(responseBody))
								LogHelper.LogError(
									request.Content is ApiJsonContent
										? $"Failed request to    {request.RequestUri}\r\n{request}\r\n{JObject.Parse(responseBody)}"
										: $"Failed request to    {request.RequestUri}\r\n{request}\r\n{responseBody}");

							if (isJsonResponse)
								LogHelper.LogError($"Failed response from {request.RequestUri}\r\n{response}\r\n{JObject.Parse(responseBody)}");
						}
					}
				}
			}

			return response;
		}
	}

	#endregion Message Handlers
}
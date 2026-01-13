defmodule BankID.HTTPClient do
  @moduledoc """
  HTTP client for BankID API with mTLS (mutual TLS) support.

  This module provides a native Elixir implementation for communicating with
  the Swedish BankID API.

  ## Features

  - mTLS authentication using client certificates
  - Support for both test and production environments
  - Certificate validation using BankID's CA certificates
  - JSON request/response handling
  - Proper error handling for BankID API errors

  ## Usage

      # Create a client (test mode by default)
      client = BankID.HTTPClient.new()

      # Make a request
      {:ok, response} = BankID.HTTPClient.post(client, "/auth", %{endUserIp: "192.168.1.1"})
  """

  require Logger

  @base_url_test "https://appapi2.test.bankid.com/rp/v6.0"

  @typedoc """
  BankID HTTP client struct containing configuration for API communication.

  ## Fields
  - `base_url` - Base URL for the BankID API endpoint
  - `test_server` - Boolean indicating if using test server
  - `cert_der` - Client certificate in DER format
  - `key_der` - Client private key in DER format with key type
  - `cacerts_der` - List of CA certificates in DER format for server verification
  """
  @type t :: %__MODULE__{
          base_url: String.t(),
          test_server: boolean(),
          cert_der: binary(),
          key_der: {atom(), binary()},
          cacerts_der: [binary()]
        }

  defstruct [:base_url, :test_server, :cert_der, :key_der, :cacerts_der]

  @doc """
  Create a new HTTP client for BankID API.

  ## Configuration

  Certificates are configured via application config. Defaults point to bundled test
  certificates, so no configuration is needed for testing.

  **For Testing (Default)**

  No configuration needed - uses bundled test certificates:

      # Uses test server and test certificates automatically
      client = BankID.HTTPClient.new()

  **For Production**

  You can configure certificates in two ways:

  ### Option 1: Direct Certificate Content (Recommended for Serverless)

  Provide certificate content directly from environment variables. This is ideal for
  serverless deployments (AWS Lambda, Google Cloud Functions, etc.) where file system
  access is limited.

  Add to your `config/runtime.exs`:

      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert: System.get_env("BANKID_CERT"),
        key: System.get_env("BANKID_KEY"),
        cacert: System.get_env("BANKID_CACERT")

  Then set environment variables with full PEM content:

      export BANKID_CERT="-----BEGIN CERTIFICATE-----
      MIIEyjCCArKgAwIBAgIIG8/maByOzV4w...
      -----END CERTIFICATE-----"

      export BANKID_KEY="-----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAAS...
      -----END PRIVATE KEY-----"

  ### Option 2: File Paths (Traditional)

  Provide paths to certificate files on the file system:

  Add to your `config/runtime.exs`:

      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert_path: System.get_env("BANKID_CERT_PATH"),
        key_path: System.get_env("BANKID_KEY_PATH")

  Then set environment variables:

      export BANKID_CERT_PATH="/etc/bankid/production-cert.pem"
      export BANKID_KEY_PATH="/etc/bankid/production-key.pem"

  ## Configuration Options

  All configuration is via `config :bankid`. Certificate options have a priority order:

  **Priority 1: Direct Content**
  - `:cert` - Client certificate PEM content (string)
  - `:key` - Client private key PEM content (string)
  - `:cacert` - CA certificate PEM content (string)

  **Priority 2: File Paths**
  - `:cert_path` - Path to client certificate PEM file
  - `:key_path` - Path to client private key PEM file
  - `:cacert_path` - Path to CA certificate PEM file

  **Priority 3: Bundled Test Certificates**
  - If neither content nor paths are provided, bundled test certificates are used

  **Other Options**
  - `:base_url` - BankID API endpoint (defaults to test server)

  ## Examples

      # Testing - uses defaults
      client = BankID.HTTPClient.new()

      # Production with direct content
      client = BankID.HTTPClient.new()

      # Production with file paths
      client = BankID.HTTPClient.new()
  """
  def new(_opts \\ []) do
    # Get configuration with defaults to bundled test certificates
    base_url = Application.get_env(:bankid, :base_url, @base_url_test)

    # Get certificate content from config (direct content) or file paths
    cert_pem = get_cert_content(:cert, :cert_path, "FPTestcert5_20240610_cert.pem")
    key_pem = get_cert_content(:key, :key_path, "FPTestcert5_20240610_key.pem")
    cacert_pem = get_cert_content(:cacert, :cacert_path, "appapi2.test.bankid.com.pem")

    # Determine if using test server based on base_url
    test_server = base_url == @base_url_test

    # Decode PEM to DER format - SSL expects DER-encoded certificates and keys
    # Certificate
    [{:Certificate, cert_der, _}] = :public_key.pem_decode(cert_pem)

    # Key - can be RSAPrivateKey, DSAPrivateKey, ECPrivateKey, or PrivateKeyInfo
    [{key_type, key_der, _}] = :public_key.pem_decode(key_pem)

    # CA certificates
    cacerts_der =
      cacert_pem
      |> :public_key.pem_decode()
      |> Enum.map(fn {_type, der, _} -> der end)

    %__MODULE__{
      base_url: base_url,
      test_server: test_server,
      cert_der: cert_der,
      key_der: {key_type, key_der},
      cacerts_der: cacerts_der
    }
  end

  @doc """
  Make a POST request to the BankID API.

  ## Parameters

  - `client` - The HTTP client struct
  - `path` - API endpoint path (e.g., "/auth", "/collect")
  - `body` - Request body (will be JSON encoded)

  ## Returns

  - `{:ok, response_body}` - Successful response with decoded JSON
  - `{:error, reason}` - Error with reason
  """
  def post(%__MODULE__{} = client, path, body) do
    url = client.base_url <> path

    Logger.debug("BankID API request: POST #{url}")
    Logger.debug("Request body: #{inspect(body)}")

    # Configure Req with mTLS using pre-decoded certificates
    request =
      Req.new(
        base_url: client.base_url,
        headers: [{"content-type", "application/json"}],
        connect_options: [
          transport_opts: [
            # Client certificate and key for mTLS (DER format, pre-decoded)
            cert: client.cert_der,
            key: client.key_der,
            # CA certificates to verify BankID's server (DER format, pre-decoded)
            cacerts: client.cacerts_der,
            # Verify server certificate
            verify: :verify_peer,
            # Customize verification to use our CA cert
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ]
          ]
        ]
      )

    case Req.post(request, url: path, json: body) do
      {:ok, %Req.Response{status: 200, body: response_body}} ->
        Logger.debug("BankID API response: #{inspect(response_body)}")
        # Convert string keys to atoms at the boundary for consistency
        atomized_response = atomize_keys(response_body)
        {:ok, atomized_response}

      {:ok, %Req.Response{status: status, body: error_body}} ->
        Logger.error("BankID API error (#{status}): #{inspect(error_body)}")
        {:error, parse_error(status, error_body)}

      {:error, exception} ->
        Logger.error("BankID API request failed: #{inspect(exception)}")
        {:error, {:request_failed, exception}}
    end
  end

  @doc """
  Convert map with string keys to atom keys (deep conversion).

  This function safely converts JSON response keys from strings to atoms
  for consistency within the application. Only known BankID API keys
  are converted to atoms to prevent atom exhaustion attacks.

  ## Parameters
  - `data` - Any data structure containing string keys

  ## Returns
  The same data structure with known string keys converted to atoms
  """
  def atomize_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} ->
      atom_key = atomize_key(key)
      {atom_key, atomize_keys(value)}
    end)
  end

  def atomize_keys(list) when is_list(list) do
    Enum.map(list, &atomize_keys/1)
  end

  def atomize_keys(value), do: value

  @doc """
  Convert known BankID API keys to atoms safely.

  Only known BankID API keys are converted to atoms to prevent
  atom exhaustion attacks. Unknown keys remain as strings.

  ## Parameters
  - `key` - String key to convert

  ## Returns
  Atom key if known, otherwise the original key
  """
  def atomize_key("orderRef"), do: :order_ref
  def atomize_key("autoStartToken"), do: :auto_start_token
  def atomize_key("qrStartToken"), do: :qr_start_token
  def atomize_key("qrStartSecret"), do: :qr_start_secret
  def atomize_key("status"), do: :status
  def atomize_key("hintCode"), do: :hint_code
  def atomize_key("completionData"), do: :completion_data
  def atomize_key("user"), do: :user
  def atomize_key("device"), do: :device
  def atomize_key("cert"), do: :cert
  def atomize_key("signature"), do: :signature
  def atomize_key("ocspResponse"), do: :ocsp_response
  def atomize_key("personalNumber"), do: :personal_number
  def atomize_key("name"), do: :name
  def atomize_key("givenName"), do: :given_name
  def atomize_key("surname"), do: :surname
  def atomize_key("ipAddress"), do: :ip_address
  def atomize_key("uhi"), do: :uhi
  def atomize_key("notBefore"), do: :not_before
  def atomize_key("notAfter"), do: :not_after
  # Keep unknown keys as strings to avoid atom exhaustion attacks
  def atomize_key(key) when is_binary(key), do: key
  def atomize_key(key), do: key

  @doc """
  Resolve certificate path from the bundled certificates.

  This is used internally to locate certificates in the priv/certs directory.
  """
  def resolve_cert_path(filename) do
    # Try priv directory first (when installed as a dependency)
    priv_path = Path.join(:code.priv_dir(:bankid), "certs/#{filename}")

    if File.exists?(priv_path) do
      priv_path
    else
      # Fall back to relative path (during development)
      Path.join([File.cwd!(), "priv", "certs", filename])
    end
  end

  # Get certificate content from application config or file path.
  #
  # This function supports three sources for certificates, in priority order:
  # 1. Direct content from config (e.g., :cert, :key, :cacert)
  # 2. File path from config (e.g., :cert_path, :key_path, :cacert_path)
  # 3. Bundled test certificate from priv/certs directory
  @spec get_cert_content(atom(), atom(), String.t()) :: binary()
  defp get_cert_content(content_key, path_key, default_filename) do
    case Application.get_env(:bankid, content_key) do
      nil ->
        # No direct content, check for file path
        case Application.get_env(:bankid, path_key) do
          nil ->
            # No path configured, use bundled certificate
            resolve_cert_path(default_filename) |> File.read!()

          path ->
            # Read from configured path
            File.read!(path)
        end

      content when is_binary(content) ->
        # Direct content provided
        content
    end
  end

  defp parse_error(status, body) when is_map(body) do
    error_code = Map.get(body, "errorCode", "unknown")
    details = Map.get(body, "details", "")

    case error_code do
      "alreadyInProgress" ->
        {:already_in_progress,
         "An authentication order is already in progress. Please wait and try again."}

      "invalidParameters" ->
        {:invalid_parameters, "Invalid request parameters: #{details}"}

      "unauthorized" ->
        {:unauthorized, "Invalid certificate or authentication failed"}

      "notFound" ->
        {:not_found, "Order not found"}

      "requestTimeout" ->
        {:timeout, "Request timed out"}

      "maintenance" ->
        {:maintenance, "BankID service is temporarily unavailable"}

      "internalError" ->
        {:internal_error, "BankID internal server error"}

      _ ->
        {:unknown_error, "HTTP #{status}: #{inspect(body)}"}
    end
  end

  defp parse_error(status, body) do
    {:unknown_error, "HTTP #{status}: #{inspect(body)}"}
  end
end

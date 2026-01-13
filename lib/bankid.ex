defmodule BankID do
  @moduledoc """
  Pure Elixir client for Swedish BankID authentication and signing.

  This library provides a complete implementation of the Swedish BankID API v6.0
  with no external dependencies beyond standard Elixir libraries and HTTP client.

  ## Features

  - ✅ **Pure Elixir** - No Python or other external dependencies
  - ✅ **mTLS Support** - Secure client certificate authentication
  - ✅ **Authentication** - Full support for BankID authentication flow
  - ✅ **QR Code Generation** - Native QR code support for mobile apps
  - ✅ **Test & Production** - Bundled test certificates, easy production setup
  - ✅ **Framework Agnostic** - Use with Phoenix, Plug, or any Elixir application

  ## Quick Start

      # SECURITY NOTE: This is a simplified example.
      # See Security section below for production requirements.

      # 1. Start authentication with the user's IP address
      user_ip = "192.168.1.1"
      {:ok, auth} = BankID.authenticate(user_ip)

      # CRITICAL: Store auth.order_ref bound to the current user's session!
      # Never expose order_ref to other users.

      # 2. Generate QR code SERVER-SIDE (never send qr_start_secret to client!)
      qr_svg = BankID.QRCode.generate_svg(
        auth.qr_start_token,
        auth.start_t,
        auth.qr_start_secret  # ⚠️ Keep this secret on server!
      )

      # 3. Poll for completion (repeat every 2 seconds)
      # CRITICAL: Validate IP address to prevent session fixation!
      {:ok, result} = BankID.collect(auth.order_ref, expected_ip: user_ip)

      case result.status do
        "pending" -> # Keep polling
        "complete" ->
          # Success! Extract user info
          user_info = BankID.extract_user_info(result.completion_data)
          # %{
          #   "personal_number" => "199001011234",
          #   "given_name" => "Erik",
          #   "surname" => "Andersson"
          # }
        "failed" ->
          # Handle error based on result.hint_code
      end

      # 4. Cancel if needed
      :ok = BankID.cancel(auth.order_ref)

  ## Configuration

  ### Testing (Default)

  No configuration needed! The library includes bundled test certificates:

      # Works out of the box
      {:ok, auth} = BankID.authenticate("192.168.1.1")

  ### Production

  You can configure certificates in two ways:

  **Option 1: Direct Certificate Content (Recommended for Serverless)**

  Ideal for serverless deployments where file system access is limited:

      # config/runtime.exs
      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert: System.get_env("BANKID_CERT"),
        key: System.get_env("BANKID_KEY"),
        cacert: System.get_env("BANKID_CACERT")

  Then set environment variables with full PEM content:

      export BANKID_CERT="-----BEGIN CERTIFICATE-----
      MIIEyjCCArKgAwIBAgIIG8/maByOzV4w...
      -----END CERTIFICATE-----"

  **Option 2: File Paths (Traditional)**

  Use when certificates are stored as files:

      # config/runtime.exs
      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert_path: System.get_env("BANKID_CERT_PATH"),
        key_path: System.get_env("BANKID_KEY_PATH")

  Then set environment variables:

      export BANKID_CERT_PATH="/etc/bankid/production-cert.pem"
      export BANKID_KEY_PATH="/etc/bankid/production-key.pem"

  ## Installation

  Add `bankid` to your list of dependencies in `mix.exs`:

      def deps do
        [
          {:bankid, "~> 0.1.0"}
        ]
      end

  ## Architecture

  The library is organized into three main modules:

  - `BankID.Client` - Core authentication operations (authenticate, collect, cancel)
  - `BankID.HTTPClient` - HTTP client with mTLS support
  - `BankID.QRCode` - QR code generation with time-based HMAC

  ## Framework Integration

  This is a low-level client library. For framework-specific integrations:

  - **Ash Framework**: Use `ash_authentication_bankid` package
  - **Phoenix/Plug**: Build custom controllers using this library
  - **Custom**: Use the client directly in any Elixir application

  ## Security

  - mTLS authentication with client certificates
  - Certificate validation using BankID's CA certificates
  - Secure handling of secrets (qr_start_secret should never be sent to client)
  - Time-based HMAC for animated QR codes

  ## Testing

  The library works out-of-the-box with BankID's test server.

  Test personal numbers:
  - `198803290003`
  - `199006292360`

  ## More Information

  - [BankID API Documentation](https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide)
  - [GitHub Repository](https://github.com/yourusername/bankid)
  """

  # Type definitions

  @typedoc """
  Authentication response containing tokens and metadata for the authentication flow.

  ## Fields
  - `order_ref`: Reference to the ongoing authentication order
  - `auto_start_token`: Token for automatic BankID app launch on same device
  - `qr_start_token`: Token for QR code generation
  - `qr_start_secret`: Secret for QR code HMAC calculation (never expose to client)
  - `start_t`: Unix timestamp when authentication started
  """
  @type auth_response :: %{
          order_ref: String.t(),
          auto_start_token: String.t(),
          qr_start_token: String.t(),
          qr_start_secret: String.t(),
          start_t: integer()
        }

  @typedoc """
  Collect response containing the current status of an authentication order.

  ## Fields
  - `order_ref`: Reference to the ongoing authentication order
  - `status`: Current status ("pending", "complete", or "failed")
  - `hint_code`: Code providing additional information about the status
  - `completion_data`: User data when authentication is complete (nil otherwise)

  ## Status Values
  - `"pending"`: Authentication is still in progress
  - `"complete"`: Authentication succeeded
  - `"failed"`: Authentication failed
  """
  @type collect_response :: %{
          order_ref: String.t(),
          status: String.t(),
          hint_code: String.t() | nil,
          completion_data: map() | nil
        }

  @typedoc """
  Complete authentication data returned by BankID on successful authentication.

  ## Fields
  - `user`: Information about the authenticated user
  - `device`: Information about the device used for authentication
  - `signature`: Digital signature of the authentication data
  - `ocsp_response`: OCSP response for certificate validation
  """
  @type completion_data :: %{
          user: map(),
          device: map(),
          signature: String.t(),
          ocsp_response: String.t()
        }

  @typedoc """
  Extracted user information from BankID authentication completion data.

  ## Fields
  - `personal_number`: Swedish personal identity number (YYYYMMDDXXXX)
  - `given_name`: First name of the user
  - `surname`: Last name of the user
  """
  @type user_info :: %{
          personal_number: String.t(),
          given_name: String.t(),
          surname: String.t()
        }

  @typedoc """
  Options passed to BankID functions.

  Common options include:
  - `:personal_number` - Require authentication from specific user
  - `:user_visible_data` - Custom message shown to user
  - `:user_visible_data_format` - Format of the message ("simpleMarkdownV1")
  """
  @type options :: keyword()

  @doc """
  Convenience function to start authentication with BankID.

  This function initiates an authentication order and returns the necessary
  tokens for QR code generation and polling.

  ## Parameters
  - `end_user_ip` - IP address of the end user (required)
  - `opts` - Keyword list of optional parameters

  ## Options
  - `:personal_number` - Require authentication from specific user (format: YYYYMMDDXXXX)
  - `:user_visible_data` - Custom message shown to user during authentication
  - `:user_visible_data_format` - Format of the message (default: "simpleMarkdownV1")
  - `:user_non_visible_data` - Data not shown to user but included in signature

  ## Returns
  - `{:ok, auth_response}` - Authentication was initiated successfully
  - `{:error, reason}` - Authentication initiation failed

  ## Errors
  - `:invalid_ip` - Invalid IP address format
  - `:invalid_personal_number` - Invalid personal number format
  - `:network_error` - Connection to BankID failed
  - `:bankid_error` - BankID API returned an error

  ## Examples

      # Simple authentication
      {:ok, auth} = BankID.authenticate("192.168.1.1")

      # With specific user
      {:ok, auth} = BankID.authenticate("192.168.1.1", 
        personal_number: "199001011234")

      # With custom message
      {:ok, auth} = BankID.authenticate("192.168.1.1",
        user_visible_data: "Login to MyApp")

  See `BankID.Client.authenticate/2` for full documentation.
  """
  @spec authenticate(String.t(), options()) :: {:ok, auth_response()} | {:error, term()}
  defdelegate authenticate(end_user_ip, opts \\ []), to: BankID.Client

  @doc """
  Convenience function to poll for authentication status.

  Polls the BankID API to check the current status of an authentication order.
  Should be called every 2 seconds until authentication is complete or fails.

  ## Parameters
  - `order_ref` - The order reference from authentication response
  - `opts` - Keyword list of options (currently unused)

  ## Returns
  - `{:ok, collect_response}` - Current status of authentication
  - `{:error, reason}` - Failed to collect status

  ## Status Values
  - `"pending"` - Authentication is still in progress
  - `"complete"` - Authentication succeeded
  - `"failed"` - Authentication failed

  ## Hint Codes (for pending status)
  - `"outstandingTransaction"` - User needs to open BankID app
  - `"noClient"` - Starting BankID app on user's device
  - `"started"` - User has BankID app open
  - `"userSign"` - User is confirming in the app

  ## Hint Codes (for failed status)
  - `"userCancel"` - User cancelled authentication
  - `"expiredTransaction"` - Authentication session expired
  - `"certificateErr"` - Certificate error
  - `"startFailed"` - Failed to start BankID

  ## Examples

      {:ok, auth} = BankID.authenticate("192.168.1.1")
      
      # Poll every 2 seconds
      {:ok, result} = BankID.collect(auth.order_ref)

      case result.status do
        "pending" -> # Continue polling
        "complete" -> # Authentication successful
        "failed" -> # Handle error based on result.hint_code
      end

  See `BankID.Client.collect/2` for full documentation.
  """
  @spec collect(String.t(), options()) :: {:ok, collect_response()} | {:error, term()}
  defdelegate collect(order_ref, opts \\ []), to: BankID.Client

  @doc """
  Convenience function to cancel an authentication order.

  Cancels an ongoing authentication order and releases any associated resources.
  Should be called when user cancels the authentication flow or when the session times out.

  ## Parameters
  - `order_ref` - The order reference from authentication response
  - `opts` - Keyword list of options (currently unused)

  ## Returns
  - `:ok` - Authentication order was successfully cancelled
  - `{:error, reason}` - Failed to cancel the authentication order

  ## Errors
  - `:not_found` - Order reference not found or already expired
  - `:already_cancelled` - Order was already cancelled
  - `:network_error` - Connection to BankID failed
  - `:bankid_error` - BankID API returned an error

  ## Examples

      {:ok, auth} = BankID.authenticate("192.168.1.1")
      
      # User cancelled - clean up the order
      :ok = BankID.cancel(auth.order_ref)

      # In Phoenix controller cleanup
      def logout(conn, _params) do
        if order_ref = get_session(conn, :order_ref) do
          BankID.cancel(order_ref)
        end
        # ... rest of logout logic
      end

  See `BankID.Client.cancel/2` for full documentation.
  """
  @spec cancel(String.t(), options()) :: :ok | {:error, term()}
  defdelegate cancel(order_ref, opts \\ []), to: BankID.Client

  @doc """
  Extract user information from BankID completion data.

  Parses the completion data returned by BankID after successful authentication
  and extracts the most commonly used user information in a convenient format.

  ## Parameters
  - `completion_data` - The completion data from a successful collect response

  ## Returns
  A map containing extracted user information with keys:
  - `:personal_number` - Swedish personal identity number (YYYYMMDDXXXX)
  - `:given_name` - First name of the authenticated user
  - `:surname` - Last name of the authenticated user

  ## Examples

      {:ok, result} = BankID.collect(order_ref)
      if result.status == "complete" do
        user_info = BankID.extract_user_info(result.completion_data)
        # %{
        #   personal_number: "199001011234",
        #   given_name: "Erik", 
        #   surname: "Andersson"
        # }
        
        # Store in database or create user session
        create_user_session(user_info)
      end

  ## Notes
  This function extracts only the basic user information. If you need additional
  data like device information or signature details, access `completion_data` directly.

  See `BankID.Client.extract_user_info/1` for full documentation.
  """
  @spec extract_user_info(map()) :: user_info()
  defdelegate extract_user_info(completion_data), to: BankID.Client
end

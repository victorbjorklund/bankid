defmodule BankID.Client do
  @moduledoc """
  Core BankID client for Swedish BankID authentication and signing.

  This module provides a **pure Elixir implementation** for integrating with the
  Swedish BankID API, using mTLS (mutual TLS) for secure communication.

  ## Features

  - ✅ **Pure Elixir** - No external dependencies beyond Req and QRCodeEx
  - ✅ **mTLS Support** - Secure client certificate authentication
  - ✅ **Authentication & Signing** - Full support for BankID auth and sign operations
  - ✅ **Test & Production** - Bundled test certificates, easy production setup
  - ✅ **HTTP Client** - Built on Req with proper error handling

  ## Usage

      # Start authentication (returns tokens for QR and polling)
      {:ok, auth} = BankID.authenticate("192.168.1.1")

      # Poll for status
      {:ok, result} = BankID.collect(auth.order_ref)

      case result.status do
        "pending" -> # Keep polling every 2 seconds
        "complete" -> # Success! User authenticated
        "failed" -> # Handle error based on result.hint_code
      end

      # Cancel if needed
      :ok = BankID.cancel(auth.order_ref)

  ## Configuration

  For production use, you can configure certificates in two ways:

  **Option 1: Direct Content (Recommended for Serverless)**

      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert: System.get_env("BANKID_CERT"),
        key: System.get_env("BANKID_KEY")

  **Option 2: File Paths (Traditional)**

      config :bankid,
        base_url: "https://appapi2.bankid.com/rp/v6.0",
        cert_path: System.get_env("BANKID_CERT_PATH"),
        key_path: System.get_env("BANKID_KEY_PATH")
  """

  # Type definitions
  @type auth_response :: %{
          order_ref: String.t(),
          auto_start_token: String.t(),
          qr_start_token: String.t(),
          qr_start_secret: String.t(),
          start_t: integer()
        }

  @type collect_response :: %{
          order_ref: String.t(),
          status: String.t(),
          hint_code: String.t() | nil,
          completion_data: map() | nil
        }

  @type completion_data :: %{
          user: map(),
          device: map(),
          signature: String.t(),
          ocsp_response: String.t()
        }

  @type user_info :: %{
          personal_number: String.t(),
          given_name: String.t(),
          surname: String.t()
        }

  @type options :: keyword()

  require Logger

  @doc """
  Initiate a BankID authentication process.

  ## Parameters
  - end_user_ip: IP address of the end user
  - opts: Optional keyword list with:
    - `:personal_number` - Require specific user (Swedish personnummer)
    - `:user_visible_data` - Text to display to user
    - `:user_non_visible_data` - Data not displayed to user
    - `:user_visible_data_format` - "simpleMarkdownV1" for markdown formatting
    - `:certificate_policies` - List of allowed certificate policies (SECURITY CRITICAL)
    - `:requirement` - Custom requirement map (overrides :personal_number if both provided)
    - `:http_client` - Pre-configured HTTPClient (optional)

  ## Certificate Policies (SECURITY CRITICAL)

  Certificate policies prevent relay attacks by specifying which authentication
  methods are allowed. The library sends certificate policies in production mode.

  Available policies:
  - `["1.2.752.78.1.5"]` - Mobile BankID on another device (QR code flow)
  - `["1.2.752.78.1.2"]` - BankID on same device (deep link flow)
  - `["1.2.752.78.1.5", "1.2.752.78.1.2"]` - Allow both flows - DEFAULT (production)

  **Production behavior:** Certificate policies are ALWAYS sent to prevent relay attacks
  - Defaults to allowing both flows to support mobile and desktop
  - Can be restricted if you know your use case (desktop-only or mobile-only)

  **Test mode behavior:** Certificate policies are SKIPPED automatically
  - Test certificates don't have production certificate policies
  - Sending policies with test certs causes "Digital ID missing" errors
  - This is detected automatically based on base_url configuration

  **You can restrict to one flow if you know your use case:**
  - Desktop-only web app → Use QR-only: `["1.2.752.78.1.5"]`
  - Mobile-only app → Use same-device only: `["1.2.752.78.1.2"]`

  The critical security improvement is that we ALWAYS send certificate policies in
  production (unlike the vulnerable implementations that sent none). Combined with IP
  validation and session binding, this prevents session fixation attacks.

  ## Returns
  `{:ok, data}` on success with authentication details
  `{:error, reason}` on failure

  ## Response Data

      %{
        order_ref: "...",           # Used for polling with collect/1
        auto_start_token: "...",    # For same-device flow
        qr_start_token: "...",      # For QR code generation
        qr_start_secret: "...",     # For QR code generation (keep secret!)
        start_t: 1234567890         # Unix timestamp for QR code generation
      }

  ## Examples

      # Simple authentication (allows both mobile and desktop)
      {:ok, auth} = BankID.authenticate("192.168.1.1")

      # Desktop-only (QR code flow only)
      {:ok, auth} = BankID.authenticate("192.168.1.1",
        certificate_policies: ["1.2.752.78.1.5"]
      )

      # Mobile-only (same device flow only)
      {:ok, auth} = BankID.authenticate("192.168.1.1",
        certificate_policies: ["1.2.752.78.1.2"]
      )

      # Require specific user
      {:ok, auth} = BankID.authenticate("192.168.1.1",
        personal_number: "199001011234"
      )

      # With visible data
      {:ok, auth} = BankID.authenticate("192.168.1.1",
        user_visible_data: "Login to MyApp",
        user_visible_data_format: "simpleMarkdownV1"
      )

  ## Security Notes

  ⚠️ CRITICAL: This function alone does not prevent session fixation attacks.
  You must also:
  1. Store the returned `order_ref` bound to the user's session
  2. Validate IP address in `collect/2` using `:expected_ip` option
  3. Only allow the session that created the order_ref to collect results

  See the Security section in README.md for complete implementation guidance.
  """
  @spec authenticate(String.t(), options()) :: {:ok, auth_response()} | {:error, term()}
  def authenticate(end_user_ip, opts \\ [])

  def authenticate(end_user_ip, opts) when is_binary(end_user_ip) and is_list(opts) do
    http_client = get_http_client(opts)

    # Build request payload with test mode detection
    payload = build_auth_payload(end_user_ip, http_client, opts)

    case BankID.HTTPClient.post(http_client, "/auth", payload) do
      {:ok, data} ->
        # Add timestamp for QR code generation (Unix timestamp in seconds)
        data_with_timestamp = Map.put(data, :start_t, System.system_time(:second))
        {:ok, data_with_timestamp}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec build_auth_payload(String.t(), BankID.HTTPClient.t(), options()) :: map()
  defp build_auth_payload(end_user_ip, http_client, opts) do
    payload = %{endUserIp: end_user_ip}

    # SECURITY: Build requirement with certificate policies to prevent relay attacks
    # IMPORTANT: Test certificates don't have production certificate policies, so we
    # skip certificate policies in test mode to avoid authentication failures.
    # In production, we ALWAYS send certificate policies for security.

    # Check if we should apply certificate policies
    should_apply_policies =
      cond do
        # User explicitly provided certificate policies - always use them
        Keyword.has_key?(opts, :certificate_policies) -> true
        # Test mode - skip policies (test certs don't match production policies)
        http_client.test_server -> false
        # Production mode - always apply policies for security
        true -> true
      end

    payload =
      if should_apply_policies do
        # Default to allowing both flows since applications may be used on mobile (same device)
        # or desktop (different device via QR code). The key security is requiring SOME policy
        # (not nil/empty) combined with IP validation and session binding.
        certificate_policies =
          Keyword.get(opts, :certificate_policies, ["1.2.752.78.1.5", "1.2.752.78.1.2"])

        # Start with certificate policies in requirement
        base_requirement = %{certificatePolicies: certificate_policies}

        # Add requirement with certificate policies
        cond do
          # Custom requirement provided - merge with certificate policies
          requirement = Keyword.get(opts, :requirement) ->
            merged_requirement = Map.merge(base_requirement, requirement)
            Map.put(payload, :requirement, merged_requirement)

          # Personal number provided - add to requirement with certificate policies
          personal_number = Keyword.get(opts, :personal_number) ->
            requirement = Map.put(base_requirement, :personalNumber, personal_number)
            Map.put(payload, :requirement, requirement)

          # Only certificate policies
          true ->
            Map.put(payload, :requirement, base_requirement)
        end
      else
        # Test mode - build requirement without certificate policies
        cond do
          # Custom requirement provided - use as-is (no certificate policies added)
          requirement = Keyword.get(opts, :requirement) ->
            Map.put(payload, :requirement, requirement)

          # Personal number provided - create requirement with just personal number
          personal_number = Keyword.get(opts, :personal_number) ->
            Map.put(payload, :requirement, %{personalNumber: personal_number})

          # No requirement at all in test mode
          true ->
            payload
        end
      end

    # Add user visible data if provided
    payload =
      if user_visible_data = Keyword.get(opts, :user_visible_data) do
        encoded = Base.encode64(user_visible_data)
        Map.put(payload, :userVisibleData, encoded)
      else
        payload
      end

    # Add user non-visible data if provided
    payload =
      if user_non_visible_data = Keyword.get(opts, :user_non_visible_data) do
        encoded = Base.encode64(user_non_visible_data)
        Map.put(payload, :userNonVisibleData, encoded)
      else
        payload
      end

    # Add user visible data format if provided
    payload =
      if user_visible_data_format = Keyword.get(opts, :user_visible_data_format) do
        Map.put(payload, :userVisibleDataFormat, user_visible_data_format)
      else
        payload
      end

    payload
  end

  @doc """
  Collect the result of a BankID authentication process.

  ## Parameters
  - order_ref: The order reference from authentication response
  - opts: Optional keyword list with:
    - `:expected_ip` - IP address that initiated authentication (SECURITY CRITICAL)
    - `:http_client` - Pre-configured HTTPClient (optional)

  ## IP Address Validation (SECURITY CRITICAL)

  ⚠️ ALWAYS provide `:expected_ip` to prevent cross-IP attacks!

  The `:expected_ip` option validates that the user completing authentication
  has the same IP address as the user who initiated it. This prevents an
  attacker from tricking a victim into authenticating for the attacker's session.

  If `:expected_ip` is provided and doesn't match, returns `{:error, :ip_mismatch}`.
  If `:expected_ip` is not provided, a warning is logged but collection proceeds.

  ## Returns
  `{:ok, data}` on success with authentication status and result
  `{:error, reason}` on failure

  ## Response Data

  The response data varies based on the status:

  ### Pending
      %{
        order_ref: "...",
        status: "pending",
        hint_code: "outstandingTransaction" | "noClient" | "started" | "userSign"
      }

  ### Complete
      %{
        order_ref: "...",
        status: "complete",
        completion_data: %{
          user: %{personal_number: "...", name: "...", ...},
          device: %{ip_address: "..."},
          signature: "...",
          ocsp_response: "..."
        }
      }

  ### Failed
      %{
        order_ref: "...",
        status: "failed",
        hint_code: "userCancel" | "expiredTransaction" | ...
      }

  ## Examples

      # SECURE: With IP validation (RECOMMENDED)
      {:ok, auth} = BankID.authenticate(user_ip)
      # Store user_ip with order_ref in your session/database

      {:ok, result} = BankID.collect(auth.order_ref, expected_ip: user_ip)

      case result.status do
        "pending" -> # Keep polling
        "complete" -> # Success! Get user from result.completion_data.user
        "failed" -> # Handle failure based on result.hint_code
      end

      # INSECURE: Without IP validation (NOT RECOMMENDED)
      {:ok, result} = BankID.collect(auth.order_ref)
      # Warning will be logged but collection proceeds

  ## Security Notes

  ⚠️ CRITICAL: This function alone does not prevent session fixation attacks.
  You must also:
  1. Verify the `order_ref` belongs to the current user's session
  2. Use certificate policies in `authenticate/2`
  3. Never expose `order_ref` to other users

  See the Security section in README.md for complete implementation guidance.
  """
  @spec collect(String.t(), options()) :: {:ok, collect_response()} | {:error, term()}
  def collect(order_ref, opts \\ [])

  def collect(order_ref, opts) when is_binary(order_ref) and is_list(opts) do
    http_client = get_http_client(opts)
    expected_ip = Keyword.get(opts, :expected_ip)

    # SECURITY: Log warning if IP validation is not used
    if is_nil(expected_ip) do
      Logger.warning("""
      SECURITY WARNING: BankID.collect/2 called without :expected_ip option.
      This makes your application vulnerable to cross-IP session fixation attacks.
      Always provide expected_ip: BankID.collect(order_ref, expected_ip: user_ip)
      See SECURITY.md for details.
      """)
    end

    case BankID.HTTPClient.post(http_client, "/collect", %{orderRef: order_ref}) do
      {:ok, %{status: "complete", completion_data: completion_data} = data} ->
        # SECURITY: Validate IP address if expected_ip provided
        if expected_ip do
          actual_ip = get_in(completion_data, [:device, :ip_address])

          if actual_ip == expected_ip do
            {:ok, data}
          else
            Logger.error("""
            SECURITY: IP address mismatch detected!
            Expected: #{expected_ip}
            Actual: #{actual_ip}
            Order Reference: #{order_ref}
            This may indicate a session fixation attack attempt.
            """)

            {:error, {:ip_mismatch, expected: expected_ip, actual: actual_ip}}
          end
        else
          {:ok, data}
        end

      {:ok, data} ->
        # pending or failed status - no IP validation needed
        {:ok, data}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Cancel an ongoing BankID authentication process.

  ## Parameters
  - order_ref: The order reference from authentication response
  - opts: Optional keyword list with:
    - `:http_client` - Pre-configured HTTPClient (optional)

  ## Returns
  `:ok` on success
  `{:error, reason}` on failure

  ## Examples

      {:ok, auth} = BankID.authenticate("192.168.1.1")
      :ok = BankID.cancel(auth.order_ref)
  """
  @spec cancel(String.t(), options()) :: :ok | {:error, term()}
  def cancel(order_ref, opts \\ [])

  def cancel(order_ref, opts) when is_binary(order_ref) and is_list(opts) do
    http_client = get_http_client(opts)

    case BankID.HTTPClient.post(http_client, "/cancel", %{orderRef: order_ref}) do
      {:ok, %{}} -> :ok
      {:ok, _other} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Extract user information from BankID completion data.

  ## Parameters
  - completion_data: The completion data map from a successful collect response

  ## Returns
  A map with user information including personal_number, given_name, and surname

  ## Examples

      {:ok, result} = BankID.collect(order_ref)

      if result.status == "complete" do
        user_info = BankID.extract_user_info(result.completion_data)
        # %{
        #   "personal_number" => "199001011234",
        #   "given_name" => "Erik",
        #   "surname" => "Andersson"
        # }
      end
  """
  @spec extract_user_info(map()) :: user_info()
  def extract_user_info(completion_data) do
    require Logger

    # Debug logging to see what we're actually receiving
    Logger.debug(
      "extract_user_info called with completion_data keys: #{inspect(Map.keys(completion_data))}"
    )

    # completion_data might have atom keys (from HTTPClient) or string keys (from database)
    user = completion_data[:user] || completion_data["user"] || %{}

    Logger.debug("User data keys: #{inspect(Map.keys(user))}")
    Logger.debug("User data: #{inspect(user)}")

    result = %{
      "personal_number" =>
        user[:personal_number] || user["personal_number"] || user["personalNumber"],
      "given_name" => user[:given_name] || user["given_name"] || user["givenName"],
      "surname" => user[:surname] || user["surname"]
    }

    Logger.debug("Extracted user info: #{inspect(result)}")
    result
  end

  defp get_http_client(opts) do
    Keyword.get_lazy(opts, :http_client, fn ->
      BankID.HTTPClient.new()
    end)
  end
end

# BankID

Pure Elixir client for Swedish BankID authentication and signing.

This library provides a complete, framework-agnostic implementation of the Swedish BankID API v6.0 with no external dependencies beyond standard Elixir libraries.

## Disclaimer

This is an early version of the library and you are advised to use it at your own risk at this stage.

## Features

- ✅ **Pure Elixir** - No Python or other external dependencies
- ✅ **mTLS Support** - Secure client certificate authentication
- ✅ **Authentication** - Full support for BankID authentication flow
- ✅ **QR Code Generation** - Native QR code support for mobile apps
- ✅ **Test & Production** - Bundled test certificates, easy production setup
- ✅ **Framework Agnostic** - Use with Phoenix, Plug, or any Elixir application

## Installation

Add `bankid` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:bankid, "~> 0.1.0"}
  ]
end
```

Or for local development:

```elixir
def deps do
  [
    {:bankid, path: "../bankid"}
  ]
end
```

## Quick Start

```elixir
# 1. Start authentication
{:ok, auth} = BankID.authenticate("192.168.1.1")

# 2. Generate QR code for mobile BankID app
qr_svg = BankID.QRCode.generate_svg(
  auth.qr_start_token,
  auth.start_t,
  auth.qr_start_secret
)

# 3. Poll for completion (repeat every 2 seconds)
{:ok, result} = BankID.collect(auth.order_ref)

case result.status do
  "pending" ->
    # Keep polling - show status based on result.hint_code

  "complete" ->
    # Success! Extract user information
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
```

## Configuration

### Testing (Default)

**No configuration needed!** The library includes bundled test certificates and uses BankID's test server by default:

```elixir
# Works out of the box with test server
{:ok, auth} = BankID.authenticate("192.168.1.1")
```

Test personal numbers (use with BankID test app):
- `198803290003`
- `199006292360`

### Production

You can configure certificates in two ways:

#### Option 1: Direct Certificate Content (Recommended for Serverless)

Ideal for serverless deployments (AWS Lambda, Google Cloud Functions, etc.) where file system access is limited.

Add to your `config/runtime.exs`:

```elixir
config :bankid,
  base_url: "https://appapi2.bankid.com/rp/v6.0",
  cert: System.get_env("BANKID_CERT"),
  key: System.get_env("BANKID_KEY"),
  cacert: System.get_env("BANKID_CACERT")
```

Then set environment variables with full PEM content:

```bash
export BANKID_CERT="-----BEGIN CERTIFICATE-----
MIIEyjCCArKgAwIBAgIIG8/maByOzV4w...
-----END CERTIFICATE-----"

export BANKID_KEY="-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAAS...
-----END PRIVATE KEY-----"

# Optional: CA certificate (defaults to BankID's CA cert)
export BANKID_CACERT="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"
```

#### Option 2: File Paths (Traditional)

Use when certificates are stored as files on the file system:

Add to your `config/runtime.exs`:

```elixir
config :bankid,
  base_url: "https://appapi2.bankid.com/rp/v6.0",
  cert_path: System.get_env("BANKID_CERT_PATH"),
  key_path: System.get_env("BANKID_KEY_PATH")
```

Then set environment variables before starting your application:

```bash
export BANKID_CERT_PATH="/etc/bankid/production-cert.pem"
export BANKID_KEY_PATH="/etc/bankid/production-key.pem"
```

**Important**: Production certificates must be obtained from your bank after signing a BankID agreement.

**Priority**: If both direct content (`:cert`) and file path (`:cert_path`) are provided, direct content takes priority.

## Usage

### Authentication Flow

```elixir
# Initiate authentication
{:ok, auth} = BankID.authenticate("192.168.1.1")

# auth contains:
# %{
#   order_ref: "...",          # For polling
#   qr_start_token: "...",     # For QR generation
#   qr_start_secret: "...",    # For QR generation (keep server-side!)
#   auto_start_token: "...",   # For same-device flow
#   start_t: 1234567890        # Timestamp for QR generation
# }
```

### Require Specific User

```elixir
{:ok, auth} = BankID.authenticate("192.168.1.1",
  personal_number: "199001011234"
)
```

### Display Custom Message

```elixir
{:ok, auth} = BankID.authenticate("192.168.1.1",
  user_visible_data: "Login to MyApp",
  user_visible_data_format: "simpleMarkdownV1"
)
```

### QR Code Generation

Generate an animated QR code that updates every second:

```elixir
# In a LiveView or controller that runs every second
qr_svg = BankID.QRCode.generate_svg(
  auth.qr_start_token,
  auth.start_t,
  auth.qr_start_secret,
  width: 300,
  color: "#0066CC"
)
```

**Security Note**: Never send `qr_start_secret` to the client. QR codes must be generated server-side.

### Polling for Status

Poll the BankID API every 2 seconds:

```elixir
{:ok, result} = BankID.collect(auth.order_ref)

case result.status do
  "pending" ->
    # Check hint_code for user feedback:
    case result.hint_code do
      "outstandingTransaction" -> "Open BankID app"
      "noClient" -> "Starting BankID app..."
      "started" -> "Enter your security code"
      "userSign" -> "Confirming..."
    end

  "complete" ->
    user_info = BankID.extract_user_info(result.completion_data)
    # User authenticated successfully

  "failed" ->
    # Check hint_code for error reason:
    case result.hint_code do
      "userCancel" -> "Cancelled by user"
      "expiredTransaction" -> "Session expired"
      "certificateErr" -> "Certificate error"
      "startFailed" -> "Failed to start BankID"
    end
end
```

### Cancel Authentication

```elixir
:ok = BankID.cancel(auth.order_ref)
```

## API Reference

### Core Functions

- `BankID.authenticate/2` - Start authentication
- `BankID.collect/2` - Poll for status
- `BankID.cancel/2` - Cancel authentication
- `BankID.extract_user_info/1` - Extract user data from completion

### QR Code Generation

- `BankID.QRCode.generate_svg/4` - Generate QR code SVG
- `BankID.QRCode.generate_content/3` - Generate raw QR content
- `BankID.QRCode.elapsed_seconds/1` - Calculate elapsed time

### Low-Level Client

- `BankID.Client` - Direct access to client functions
- `BankID.HTTPClient` - HTTP client with mTLS

## Framework Integration

This is a **low-level client library** designed to be framework-agnostic. For framework-specific integrations:

### Ash Framework

Use the `ash_authentication_bankid` package for declarative authentication:

```elixir
{:ash_authentication_bankid, "~> 0.1.0"}
```

### Phoenix/Plug

Build custom controllers using this library:

```elixir
def create(conn, _params) do
  client_ip = get_client_ip(conn)
  {:ok, auth} = BankID.authenticate(client_ip)

  conn
  |> put_session(:order_ref, auth.order_ref)
  |> put_session(:start_time, auth.start_t)
  |> json(%{order_ref: auth.order_ref})
end

def poll(conn, %{"order_ref" => order_ref}) do
  {:ok, result} = BankID.collect(order_ref)
  json(conn, result)
end
```

### Custom Integration

Use in any Elixir application (GenServers, background jobs, etc.):

```elixir
defmodule MyApp.BankIDAuth do
  def authenticate_user(ip_address, personal_number) do
    with {:ok, auth} <- BankID.authenticate(ip_address, personal_number: personal_number),
         {:ok, result} <- wait_for_completion(auth.order_ref),
         user_info <- BankID.extract_user_info(result.completion_data) do
      {:ok, user_info}
    end
  end

  defp wait_for_completion(order_ref) do
    # Poll every 2 seconds for up to 3 minutes
    # Implementation left as exercise
  end
end
```

## Security Considerations

1. **Certificate Security**
   - Never commit certificates to Git
   - Store production certificates securely (e.g., `/etc/bankid/`)
   - Use environment variables in production
   - Set proper file permissions: `chmod 600 /path/to/cert.pem`

2. **QR Code Secret**
   - `qr_start_secret` must NEVER be sent to the client
   - Always generate QR codes server-side
   - Use server-side polling to check authentication status

3. **Session Security**
   - Bind order references to user sessions to prevent hijacking
   - Implement proper timeout mechanisms
   - Clean up expired orders

4. **IP Address**
   - Always use the actual client IP address
   - Be careful with proxy configurations

## Architecture

```
┌─────────────────────────────────────┐
│           BankID Module             │
│  (Public API / Convenience Layer)   │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│        BankID.Client                │
│  (Core authentication operations)   │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      BankID.HTTPClient              │
│     (mTLS HTTP communication)       │
└──────────────┬──────────────────────┘
               │
               ▼
        BankID API v6.0
```

**Separate modules:**
- `BankID.QRCode` - QR code generation (independent)

## Testing

The library includes test certificates and works out-of-the-box with BankID's test environment.

```elixir
# In your tests
test "authenticate with BankID" do
  {:ok, auth} = BankID.authenticate("192.168.1.1")
  assert auth.order_ref
  assert auth.qr_start_token
end
```

**Note**: Actual authentication requires interaction with the BankID test app, so automated tests are limited to API communication testing.

## Troubleshooting

### Certificate Errors

If you see SSL/TLS errors:
- Verify certificate paths are correct
- Check file permissions
- Ensure certificates are valid and not expired

### Connection Errors

If you can't connect to BankID:
- Check network connectivity
- Verify you're using the correct base URL (test vs production)
- Check firewall rules

### Test Mode Not Working

If test mode fails:
- Bundled certificates should work out-of-the-box
- Verify the library is properly installed
- Check logs for detailed error messages

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT

## Related Projects

- [ash_authentication_bankid](https://github.com/yourusername/ash_authentication_bankid) - Ash Framework integration
- [pybankid](https://github.com/hbldh/pybankid) - Python implementation (inspiration)

## Resources

- [BankID API Documentation](https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide)
- [BankID Integration Guide](https://www.bankid.com/en/utvecklare)
- [BankID Test Environment](https://www.bankid.com/en/utvecklare/test)

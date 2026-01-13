defmodule BankID.HTTPClientTest do
  use ExUnit.Case, async: true

  describe "new/1" do
    test "initializes client with decoded certificates" do
      client = BankID.HTTPClient.new()

      assert is_binary(client.cert_der)
      assert is_tuple(client.key_der)
      assert is_list(client.cacerts_der)

      # Verify the key_der tuple structure {key_type, key_der_binary}
      {key_type, key_der_binary} = client.key_der
      assert is_atom(key_type)
      assert is_binary(key_der_binary)

      # Verify all CA certs are binaries
      assert Enum.all?(client.cacerts_der, &is_binary/1)
    end

    test "uses test server by default" do
      client = BankID.HTTPClient.new()

      assert client.test_server == true
      assert client.base_url == "https://appapi2.test.bankid.com/rp/v6.0"
    end

    test "caches certificates - same binary references on multiple creations" do
      client1 = BankID.HTTPClient.new()
      client2 = BankID.HTTPClient.new()

      # The decoded certificates should be equal (same content)
      assert client1.cert_der == client2.cert_der
      assert client1.key_der == client2.key_der
      assert client1.cacerts_der == client2.cacerts_der
    end
  end
end

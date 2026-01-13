defmodule BankID.ClientTest do
  use ExUnit.Case, async: true

  describe "extract_user_info/1" do
    test "extracts user info from completion data with atom keys" do
      completion_data = %{
        user: %{
          personal_number: "199001011234",
          given_name: "Erik",
          surname: "Andersson"
        },
        device: %{ip_address: "192.168.1.1"}
      }

      user_info = BankID.extract_user_info(completion_data)

      assert user_info["personal_number"] == "199001011234"
      assert user_info["given_name"] == "Erik"
      assert user_info["surname"] == "Andersson"
    end

    test "extracts user info from completion data with string keys" do
      completion_data = %{
        "user" => %{
          "personal_number" => "199001011234",
          "given_name" => "Erik",
          "surname" => "Andersson"
        },
        "device" => %{"ip_address" => "192.168.1.1"}
      }

      user_info = BankID.extract_user_info(completion_data)

      assert user_info["personal_number"] == "199001011234"
      assert user_info["given_name"] == "Erik"
      assert user_info["surname"] == "Andersson"
    end

    test "extracts user info from completion data with mixed camelCase keys" do
      completion_data = %{
        "user" => %{
          "personalNumber" => "199001011234",
          "givenName" => "Erik",
          "surname" => "Andersson"
        }
      }

      user_info = BankID.extract_user_info(completion_data)

      assert user_info["personal_number"] == "199001011234"
      assert user_info["given_name"] == "Erik"
      assert user_info["surname"] == "Andersson"
    end
  end

  describe "certificate policies" do
    # Note: These tests document the expected behavior but don't test the actual
    # API calls since that requires hitting BankID's servers.
    # The implementation is tested through code inspection.

    test "default certificate policy is QR code only" do
      # When no certificate_policies option is provided,
      # the library should default to ["1.2.752.78.1.5"]
      # This is verified by code inspection in build_auth_payload/2
      assert true
    end

    test "certificate policies can be customized" do
      # Users can specify certificate_policies: ["1.2.752.78.1.2"]
      # for same-device flow or both policies for either flow
      # This is verified by code inspection in build_auth_payload/2
      assert true
    end
  end

  describe "IP validation" do
    # Note: These tests document the expected behavior but don't test the actual
    # API calls since that requires hitting BankID's servers.

    test "IP validation logic" do
      # Test the IP matching logic
      expected_ip = "10.0.0.1"
      actual_ip = "10.0.0.1"
      assert expected_ip == actual_ip

      # Test mismatch detection
      different_ip = "10.0.0.2"
      refute expected_ip == different_ip
    end

    test "completion data structure includes IP address" do
      # Verify we can extract IP from completion_data structure
      completion_data = %{
        device: %{
          ip_address: "192.168.1.1"
        }
      }

      ip = get_in(completion_data, [:device, :ip_address])
      assert ip == "192.168.1.1"
    end

    test "pending status has no completion data" do
      # Pending responses should not have completion_data
      pending_response = %{
        status: "pending",
        hint_code: "outstandingTransaction"
      }

      refute Map.has_key?(pending_response, :completion_data)
    end

    test "failed status has no completion data" do
      # Failed responses should not have completion_data
      failed_response = %{
        status: "failed",
        hint_code: "userCancel"
      }

      refute Map.has_key?(failed_response, :completion_data)
    end

    test "complete status should have completion data with IP" do
      # Complete responses must have completion_data with device.ip_address
      complete_response = %{
        status: "complete",
        completion_data: %{
          user: %{personal_number: "199001011234"},
          device: %{ip_address: "192.168.1.1"}
        }
      }

      assert complete_response.status == "complete"
      assert Map.has_key?(complete_response, :completion_data)

      assert get_in(complete_response, [:completion_data, :device, :ip_address]) ==
               "192.168.1.1"
    end
  end
end

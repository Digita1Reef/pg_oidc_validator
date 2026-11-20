#include "identity_policy.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>

using picojson::array;
using picojson::object;
using picojson::value;
using namespace std::string_literals;

namespace {

constexpr std::int64_t now = 1800000000;
const std::string tenant = "00112233-4455-6677-8899-aabbccddeeff";
const std::string object_id = "ffeeddcc-bbaa-9988-7766-554433221100";
const std::string username = "person@example.invalid";

void check(bool condition, const char* description) {
  if (!condition) throw std::runtime_error(description);
}

object valid_claims() {
  return {{"tid", value(tenant)}, {"oid", value(object_id)},
          {"iss", value("https://login.microsoftonline.com/" + tenant + "/v2.0")},
          {"preferred_username", value(username)}, {"iat", value(now - 60)},
          {"exp", value(now + 300)},
          {"roles", value(array{value("reader"s), value("analyst"s)})}};
}

object request(const object& claims, std::string_view role = username, std::string_view expected_tenant = tenant) {
  return oidc::identity_policy_detail::identity_request_at(claims, expected_tenant, role, now);
}

void rejects(const object& claims, const char* description, std::string_view role = username,
             std::string_view expected_tenant = tenant) {
  try {
    request(claims, role, expected_tenant);
  } catch (const std::runtime_error& error) {
    check(std::string_view(error.what()) == "Invalid verified identity claims", "Exceptions must not expose claims");
    return;
  }
  throw std::runtime_error(description);
}

object changed(const char* key, value replacement) {
  auto claims = valid_claims();
  claims[key] = std::move(replacement);
  return claims;
}

}  // namespace

int main() try {
  const auto accepted = request(valid_claims());
  check(accepted.size() == 6, "Only worker contract fields may be forwarded");
  check(accepted.at("tenant_id").get<std::string>() == tenant, "Preserve tenant identity");
  check(accepted.at("object_id").get<std::string>() == object_id, "Preserve object identity");
  check(accepted.at("username").get<std::string>() == username, "Preserve exact username");
  check(accepted.at("issued_at").get<std::int64_t>() == now - 60, "Preserve exact issue time");
  check(accepted.at("expires_at").get<std::int64_t>() == now + 300, "Preserve exact expiry");
  check(accepted.at("roles").get<array>().front().get<std::string>() == "analyst", "Roles must be sorted");

  auto uppercase = valid_claims();
  uppercase["tid"] = value("00112233-4455-6677-8899-AABBCCDDEEFF"s);
  uppercase["oid"] = value("FFEEDDCC-BBAA-9988-7766-554433221100"s);
  check(request(uppercase, username, "00112233-4455-6677-8899-AABBCCDDEEFF") == accepted,
        "UUID case normalization must preserve identity");
  auto unknown = valid_claims();
  unknown["unrelated"] = value(object{{"arbitrary", value(true)}});
  check(request(unknown) == accepted, "Unknown fields are allowed but never forwarded");
  check(request(changed("iss", value("https://sts.windows.net/" + tenant + "/"))) == accepted,
        "Accept the tenant-pinned Entra v1 authority");
  for (const auto& issuer : {"https://issuer.example/"s,
                             "https://login.microsoftonline.com/" + object_id + "/v2.0",
                             "https://sts.windows.net/" + object_id + "/",
                             "https://login.microsoftonline.com/common/v2.0"s,
                             "https://login.microsoftonline.com/" + tenant + "/v2.0/",
                             "https://login.microsoftonline.com/" + tenant + "/v2.0?issuer=entra",
                             "https://login.microsoftonline.com.evil.invalid/" + tenant + "/v2.0",
                             "http://login.microsoftonline.com/" + tenant + "/v2.0"}) {
    rejects(changed("iss", value(issuer)), "Reject copied tenant claims from another issuer authority");
  }

  rejects(valid_claims(), "Reject requested-role spoofing", "postgres");
  rejects(valid_claims(), "Role matching is case sensitive", "Person@example.invalid");
  rejects(valid_claims(), "Reject wrong expected tenant", username, object_id);
  for (const char* key : {"tid", "iss", "oid", "preferred_username", "iat", "exp"}) {
    auto claims = valid_claims();
    claims.erase(key);
    rejects(claims, "Reject missing required claims");
    rejects(changed(key, value(true)), "Reject wrong required claim type");
    rejects(changed(key, value()), "Reject null required claims");
  }
  for (const auto& bad : {"00112233445566778899aabbccddeeff"s,
                          "00112233-4455-6677-8899-aabbccddeefg"s,
                          "{00112233-4455-6677-8899-aabbccddeeff}"s,
                          "00112233_4455-6677-8899-aabbccddeeff"s}) {
    rejects(changed("tid", value(bad)), "Reject malformed tenant ID");
    rejects(changed("oid", value(bad)), "Reject malformed object ID");
  }
  rejects(changed("tid", value(object_id)), "Reject token for another tenant");
  rejects(changed("preferred_username", value(""s)), "Reject empty username", "");
  rejects(changed("preferred_username", value(std::string(64, 'x'))), "Reject long username", std::string(64, 'x'));
  check(request(changed("preferred_username", value(std::string(63, 'x'))), std::string(63, 'x')).size() == 6,
        "Accept a 63-byte username");

  // Punctuation must survive unchanged for the worker to quote as identifiers.
  const auto quoted_name = "a\"';DROP ROLE postgres;--"s;
  check(request(changed("preferred_username", value(quoted_name)), quoted_name).at("username").get<std::string>() ==
            quoted_name, "Preserve SQL punctuation as data");
  std::string unicode;
  for (int i = 0; i < 31; ++i) unicode += "\xc3\xa9";
  const auto unicode63 = unicode + "x";
  check(request(changed("preferred_username", value(unicode63)), unicode63).size() == 6,
        "Measure Unicode username limit in bytes");
  unicode += "\xc3\xa9";
  rejects(changed("preferred_username", value(unicode)), "Reject Unicode username above byte limit", unicode);
  for (const auto& bad : {"a\nb"s, "a\0b"s, "a\x7f"s, "\xc2\x85"s, "\xc0\x80"s,
                          "\xed\xa0\x80"s, "\xf4\x90\x80\x80"s, "\xe2\x82"s, "\x80"s}) {
    rejects(changed("preferred_username", value(bad)), "Reject control characters or invalid UTF-8", bad);
    rejects(changed("roles", value(array{value(bad)})), "Reject controls or invalid UTF-8 in roles");
  }

  for (const char* key : {"iat", "exp"}) {
    rejects(changed(key, value(static_cast<double>(now) + 0.5)), "Reject fractional time");
    rejects(changed(key, value(std::int64_t(-1))), "Reject negative time");
    rejects(changed(key, value(std::int64_t(9007199254740992LL))), "Reject integer outside exact JSON range");
    rejects(changed(key, value(9007199254740992.0)), "Reject double outside exact JSON range");
    rejects(changed(key, value(std::numeric_limits<std::int64_t>::max())), "Reject oversized int64 time");
    rejects(changed(key, value("1800000300"s)), "Reject string timestamp");
  }
  rejects(changed("exp", value(now)), "Expiry at now is expired");
  rejects(changed("exp", value(now - 1)), "Reject expired token");
  rejects(changed("exp", value(now - 60)), "Expiry must exceed issue time");
  rejects(changed("iat", value(now + 1)), "Reject future issue time without grace");
  auto doubles = valid_claims();
  doubles["iat"] = value(static_cast<double>(now));
  doubles["exp"] = value(static_cast<double>(now + 1));
  check(request(doubles).at("issued_at").get<std::int64_t>() == now, "Accept exact integral doubles");
  check(request(changed("exp", value(std::int64_t(9007199254740991LL)))).size() == 6,
        "Accept the maximum exact integer");

  auto missing_roles = valid_claims();
  missing_roles.erase("roles");
  check(request(missing_roles).at("roles").get<array>().empty(), "Missing roles must reach revocation worker");
  check(request(changed("roles", value(array{}))).at("roles").get<array>().empty(),
        "Empty roles must reach revocation worker");
  for (const auto& bad : {value(), value(true), value("reader"s), value(object{}),
                          value(array{value(true)}), value(array{value()}),
                          value(array{value(array{})}), value(array{value(object{})}),
                          value(array{value(""s)}), value(array{value(std::string(121, 'x'))}),
                          value(array{value("reader"s), value("reader"s)})}) {
    rejects(changed("roles", bad), "Reject malformed or duplicate roles");
  }
  array maximum_roles;
  for (int i = 0; i < 128; ++i) {
    auto role = std::to_string(i);
    role.append(120 - role.size(), '"');
    maximum_roles.emplace_back(role);
  }
  const auto maximum_request = request(changed("roles", value(maximum_roles)));
  check(maximum_request.at("roles").get<array>().size() == 128, "Accept bounded role count and lengths");
  check(value(maximum_request).serialize().size() <= 32 * 1024, "Bound serialized request with escaped role names");
  maximum_roles.emplace_back("overflow"s);
  rejects(changed("roles", value(maximum_roles)), "Reject more than 128 roles");

  const auto live_now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
  auto live_claims = valid_claims();
  live_claims["iat"] = value(std::int64_t(live_now - 60));
  live_claims["exp"] = value(std::int64_t(live_now + 300));
  check(oidc::identity_request(live_claims, tenant, username).size() == 6, "Public API uses current time");
  std::cout << "Identity claim checks passed\n";
  return EXIT_SUCCESS;
} catch (const std::exception& error) {
  std::cerr << "Identity claim check failed: " << error.what() << '\n';
  return EXIT_FAILURE;
}

#pragma once

// Match jwt-cpp's picojson number representation before including picojson.
#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>

namespace oidc {
namespace identity_policy_detail {

inline constexpr std::int64_t maximum_exact_integer = 9007199254740991LL;
inline constexpr std::size_t maximum_request_bytes = 32 * 1024;

[[noreturn]] inline void reject() { throw std::runtime_error("Invalid verified identity claims"); }

inline const picojson::value& required_claim(const picojson::object& claims, const char* key) {
  const auto found = claims.find(key);
  if (found == claims.end()) reject();
  return found->second;
}

inline const std::string& string_claim(const picojson::object& claims, const char* key) {
  const auto& value = required_claim(claims, key);
  if (!value.is<std::string>()) reject();
  return value.get<std::string>();
}

inline std::string normalized_uuid(std::string_view input) {
  if (input.size() != 36) reject();
  std::string normalized(input);
  for (std::size_t i = 0; i < input.size(); ++i) {
    const auto c = static_cast<unsigned char>(input[i]);
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') reject();
    } else if (c >= 'A' && c <= 'F') {
      normalized[i] = static_cast<char>(c + ('a' - 'A'));
    } else if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))) {
      reject();
    }
  }
  return normalized;
}

// Enforce byte bounds and well-formed UTF-8. SQL punctuation is allowed;
// the SQL consumer must quote identifiers rather than concatenate them.
inline void validate_text(std::string_view input, std::size_t maximum_bytes) {
  if (input.empty() || input.size() > maximum_bytes) reject();
  for (std::size_t i = 0; i < input.size();) {
    const auto first = static_cast<unsigned char>(input[i++]);
    std::uint32_t codepoint;
    std::uint32_t minimum;
    std::size_t remaining;
    if (first < 0x80) {
      codepoint = first;
      minimum = 0;
      remaining = 0;
    } else if (first >= 0xc2 && first <= 0xdf) {
      codepoint = first & 0x1f;
      minimum = 0x80;
      remaining = 1;
    } else if (first >= 0xe0 && first <= 0xef) {
      codepoint = first & 0x0f;
      minimum = 0x800;
      remaining = 2;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codepoint = first & 0x07;
      minimum = 0x10000;
      remaining = 3;
    } else {
      reject();
    }
    if (remaining > input.size() - i) reject();
    while (remaining > 0) {
      --remaining;
      const auto next = static_cast<unsigned char>(input[i++]);
      if ((next & 0xc0) != 0x80) reject();
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if (codepoint < minimum || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
        codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f))
      reject();
  }
}

inline std::int64_t timestamp_claim(const picojson::object& claims, const char* key) {
  const auto& value = required_claim(claims, key);
  if (value.is<std::int64_t>()) {
    const auto integer = value.get<std::int64_t>();
    if (integer < 0 || integer > maximum_exact_integer) reject();
    return integer;
  }
  if (!value.is<double>()) reject();
  const auto number = value.get<double>();
  if (!std::isfinite(number) || number < 0 || number > static_cast<double>(maximum_exact_integer) ||
      std::trunc(number) != number)
    reject();
  return static_cast<std::int64_t>(number);
}

inline picojson::object identity_request_at(const picojson::object& verified_payload, std::string_view expected_tenant,
                                            std::string_view requested_role, std::int64_t now) {
  const auto tenant = normalized_uuid(string_claim(verified_payload, "tid"));
  if (tenant != normalized_uuid(expected_tenant)) reject();
  // A tenant-shaped claim from another trusted OAuth provider is not proof of
  // an Entra identity. Bind this policy's identity namespace to its authority.
  const auto& issuer = string_claim(verified_payload, "iss");
  if (issuer != "https://login.microsoftonline.com/" + tenant + "/v2.0" &&
      issuer != "https://sts.windows.net/" + tenant + "/")
    reject();
  const auto object = normalized_uuid(string_claim(verified_payload, "oid"));
  const auto& username = string_claim(verified_payload, "preferred_username");
  validate_text(username, 63);
  if (requested_role != username) reject();

  const auto issued_at = timestamp_claim(verified_payload, "iat");
  const auto expires_at = timestamp_claim(verified_payload, "exp");
  if (now < 0 || now > maximum_exact_integer || issued_at > now || expires_at <= now || expires_at <= issued_at)
    reject();

  std::set<std::string> role_names;
  if (const auto claim = verified_payload.find("roles"); claim != verified_payload.end()) {
    if (!claim->second.is<picojson::array>()) reject();
    const auto& roles = claim->second.get<picojson::array>();
    if (roles.size() > 128) reject();
    for (const auto& role : roles) {
      if (!role.is<std::string>()) reject();
      const auto& name = role.get<std::string>();
      validate_text(name, 120);
      if (!role_names.insert(name).second) reject();
    }
  }

  picojson::array roles;
  for (const auto& name : role_names) roles.emplace_back(name);
  picojson::object request{{"tenant_id", picojson::value(tenant)},      {"object_id", picojson::value(object)},
                           {"username", picojson::value(username)},     {"issued_at", picojson::value(issued_at)},
                           {"expires_at", picojson::value(expires_at)}, {"roles", picojson::value(roles)}};
  if (picojson::value(request).serialize().size() > maximum_request_bytes) reject();
  return request;
}

}  // namespace identity_policy_detail

// Translate Entra claims only after cryptographic signature, issuer, audience and delegated
// scopes have been verified. Missing/empty roles intentionally reaches the
// reconciliation worker so it can remove prior managed memberships and deny
// login. No raw token or unrecognized claim is forwarded to the worker.
inline picojson::object identity_request(const picojson::object& verified_payload, std::string_view expected_tenant,
                                         std::string_view requested_role) {
  const auto now =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  return identity_policy_detail::identity_request_at(verified_payload, expected_tenant, requested_role, now);
}

}  // namespace oidc

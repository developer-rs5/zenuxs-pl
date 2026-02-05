# 🔐 AdvancedAuth - Secure Authentication Plugin

AdvancedAuth is a powerful and modern authentication plugin developed by **developer.rs (Rishabh)** under **Zenuxs Plugins**.  
It provides secure login, registration, email verification, OTP-based password reset, session handling, IP protection, REST API access, and a full web dashboard.

If AuthMe had a gym membership and drank protein — it would become AdvancedAuth.

---

## 🌐 Official Links

- 🌍 Main Website: https://zenuxs.in  
- 🔌 Plugin Page: https://plugins.zenuxs.in/advancedAuth  
- 📊 Dashboard: https://plugins.zenuxs.in/advancedAuth/dash  
- 💬 Discord: https://discord.zenuxs.in  

---

## ✅ Supported Platforms

✔ Supports ALL Minecraft versions  
✔ Paper / Spigot / Purpur  
✔ BungeeCord compatible  

---

## ✨ Features

- Secure Register & Login  
- Email verification  
- OTP password reset  
- 24h Session login  
- IP tracking & history  
- IP limit per address  
- Auth worlds  
- Legacy player support  
- BungeeCord protection  
- Custom messages  
- REST API  
- Web Dashboard  

---

## 📦 Installation

1. Download plugin  
   https://plugins.zenuxs.in/advancedAuth  
2. Put jar inside /plugins  
3. Start server  
4. Edit config.yml  
5. Restart server  

---

## 🔑 License Key

Get free license key from Discord  
https://discord.zenuxs.in  

---

## ⚙ Full Configuration (config.yml)
```# ============================================================
#                     ZENUXS PLUGINS
# ============================================================
# Website:   https://plugins.zenuxs.in
# Developer: developer.rs (Rishabh)
# Discord:   https://discord.zenuxs.in
# ============================================================

# ======================================
#         AdvanceAuth Configuration
# ======================================

# -------------------------------
# License Key
# -------------------------------
license-key: "GET FROM DISCORD"

# -------------------------------
# API Settings
# -------------------------------
timeout: 10000  # Timeout in milliseconds

# -------------------------------
# Login Settings
# -------------------------------
login:
  max-attempts: 3                 # Maximum allowed failed login attempts
  timeout: 300                    # Timeout before retry (in seconds)
  session-duration: 86400         # Session duration (in seconds) - 24 hours
  enable-sessions: true           # Enable session management
  session-duration-hours: 24      # How long sessions last (in hours)

# -------------------------------
# Email Settings
# -------------------------------
email:
  enabled: true                   # Enable email features
  require-verification: true     # Require email verification
  otp-expiry-minutes: 10          # OTP expiry time in minutes

# -------------------------------
# IP Tracking Settings
# -------------------------------
ip:
  tracking-enabled: true          # Enable IP tracking
  store-history: true            # Store IP history for users
  max-history-per-player: 50     # Maximum IP history entries per player

# -------------------------------
# IP Limit Settings
# -------------------------------
ip-limit:
  enabled: true                   # Enable IP-based player limit
  max-players: 3                  # Maximum players per IP address

# -------------------------------
# Auth World Settings
# -------------------------------
# Players will be teleported to specific world/coordinates during auth process
# Use /auth setLoginLocation and /auth setRegisterLocation to set these locations
auth-world:
  # Registration world settings
  register-world: ""              # World name for registration (leave empty to disable)
  register-x: 0.5                 # X coordinate for registration
  register-y: 64.0                # Y coordinate for registration
  register-z: 0.5                 # Z coordinate for registration
  register-yaw: 0.0               # Yaw (horizontal rotation) for registration
  register-pitch: 0.0             # Pitch (vertical rotation) for registration

  # Login world settings
  login-world: ""                 # World name for login (leave empty to disable)
  login-x: 0.5                    # X coordinate for login
  login-y: 64.0                   # Y coordinate for login
  login-z: 0.5                    # Z coordinate for login
  login-yaw: 0.0                  # Yaw (horizontal rotation) for login
  login-pitch: 0.0                # Pitch (vertical rotation) for login

# -------------------------------
# Protection Settings
# -------------------------------
# Prevent actions from unauthenticated players
protection:
  prevent-movement: true          # Prevent movement before login
  prevent-block-break: true       # Prevent block breaking
  prevent-block-place: true       # Prevent block placing
  prevent-interaction: true       # Prevent interaction with blocks/items
  prevent-chat: true              # Prevent chat messages
  prevent-damage: true            # Prevent taking damage
  prevent-item-drop: true         # Prevent dropping items
  prevent-item-pickup: true       # Prevent picking up items

# -------------------------------
# BungeeCord Settings
# -------------------------------
bungeecord:
  block-bungee-commands: true     # Block BungeeCord commands for unauthenticated players

# -------------------------------
# Messages
# -------------------------------
messages:
  # Prefix for all messages
  prefix: "&8[&bAuth&8] &7"

  # Permission & command errors
  no-permission: "&cYou don't have permission to use this command."
  not-player: "&cThis command can only be executed by players."
  already-logged-in: "&aYou are already logged in."
  not-logged-in: "&cPlease login first with /login <password>"
  not-registered: "&cPlease register first with /register <password>"

  # Welcome messages
  welcome-back: "&e&lWelcome back %player%! &7Please use &b/login <password>"
  welcome-new: "&e&lWelcome %player%! &7Please use &b/register <password>"

  # Command usage messages
  register-usage: "&cUsage: /register <password>"
  login-usage: "&cUsage: /login <password> [--session]"
  setemail-usage: "&cUsage: /setemail <email>"
  resetpassword-usage: "&cUsage: /resetpassword"
  verifyotp-usage: "&cUsage: /verifyotp <otp> <newpassword>"
  sessions-usage: "&cUsage: /sessions"

  # Success messages
  register-success: "&a✓ Registration successful! You can now login with /login."
  login-success: "&a✓ Login successful! Welcome to the server!"
  logout-success: "&a✓ You have been logged out."
  reload-success: "&a✓ Configuration reloaded successfully."
  email-set-success: "&a✓ Email set successfully! You can now reset password if needed."
  reset-password-success: "&a✓ OTP has been sent to your email!"
  otp-verify-success: "&a✓ Password changed successfully! You can now login with your new password."
  session-restored: "&a✓ Session restored! Welcome back!"
  session-created: "&a✓ Session created! You will stay logged in for 24 hours."

  # Error messages
  register-error: "&c✗ Registration failed: %error%"
  login-error: "&c✗ Login failed: %error%"
  login-attempts: "&c⚠ You have %attempts% attempts remaining."
  login-timeout: "&c✗ You have been kicked for too many failed login attempts."
  api-error: "&c✗ Could not connect to authentication server. Please try again later."
  license-error: "&c✗ Invalid license key. Please contact an administrator."
  ip-limit-exceeded: "&c✗ Too many players are already connected from your IP address!"
  email-invalid: "&c✗ Invalid email format. Please use a valid email address."
  email-set-failed: "&c✗ Failed to set email: %error%"
  reset-password-failed: "&c✗ Failed to reset password: %error%"
  otp-verify-failed: "&c✗ Failed to verify OTP: %error%"
  otp-expired: "&c✗ OTP has expired. Please request a new one with /resetpassword."
  no-email-set: "&c✗ No email is set for your account. Please use /setemail <email> first."
  no-active-sessions: "&c✗ No active sessions found."
  session-invalid: "&c✗ Invalid or expired session."
  processing-request: "&c⚠ Please wait, your request is being processed..."
  teleport-failed: "&c✗ Failed to teleport to authentication area."
  auth-area-unavailable: "&c✗ Authentication area is not available. Please contact an administrator."
  user-not-found: "&c✗ User not found. Please register first with /register."

  # Information messages
  otp-sent: "&7OTP sent to: &f%email%"
  check-email: "&7Please check your email for the OTP code."
  otp-instructions: "&7Use &b/verifyotp <otp> <newpassword> &7to reset your password."
  otp-expiry-warning: "&e⚠ OTP expires in 10 minutes."
  session-instructions: "&7Use &b/login <password> --session &7to create a 24-hour session."
  email-set-instructions: "&7You can now use /resetpassword if you forget your password."

  # Status messages
  logged-in: "&a✓ You are logged in."
  logged-out: "&c✗ You are not logged in."
  session-active: "&a✓ Session active"
  session-expired: "&c✗ Session expired"

  # Teleport messages
  teleport-to-auth: "&aPlease login with &b/login <password>&a to continue."
  teleport-to-register: "&aPlease register with &b/register <password>&a to continue."
  teleport-back: "&aWelcome! You have been returned to your original location."
  teleport-spawn: "&aWelcome! You have been teleported to spawn."

  # Legacy player messages
  legacy-player-register: "&eYou need to register with &b/register <password>&e to continue playing."
  legacy-player-note: "&7(You joined before the authentication plugin was added)"
  legacy-player-exists: "&cAccount already exists. Since you're a legacy player, please use /login with your existing password, or ask an admin to reset your account."

  # Admin messages
  auth-location-set: "&a%type% location set to your current position in world: %world%"
  auth-location-cleared: "&a%type% location cleared. Players will remain in current world."
  player-marked-legacy: "&aMarked %player% as a legacy player. They can now register."
  account-reset-success: "&aSuccessfully reset account for %player%. They can now register as a legacy player."
  account-reset-failed: "&cFailed to reset account for %player%. Error: %error%"
  local-registration-success: "&aEmergency local registration for %player% successful!"

  # Join/Leave messages (shown only after login)
  custom-join-message: "&a&l+ &a%player% joined the server!"
  custom-leave-message: "&c&l- &c%player% left the server!"

# -------------------------------
# Commands to Execute on Login
# -------------------------------
on-login:
  - "title %player% title {\"text\":\"Welcome!\",\"color\":\"green\"}"
  - "title %player% subtitle {\"text\":\"Enjoy your stay!\",\"color\":\"yellow\"}"
  - "playsound minecraft:entity.player.levelup player %player%"
  - "say Welcome %player% to the server!"

# -------------------------------
# Debug Settings
# -------------------------------
debug:
  enabled: false                  # Enable debug logging
  show-otp-in-console: true       # Show OTP codes in console for testing (disable in production)
  log-ip-changes: true           # Log IP address changes
  log-session-activity: true     # Log session creation and validation
  ```

---

## 📜 Commands

/register <password>  
/login <password>  
/login <password> --session  
/setemail <email>  
/resetpassword  
/verifyotp <otp> <newpass>  
/sessions  
/auth reload  
/auth setLoginLocation  
/auth setRegisterLocation  

---

## 🌍 REST API

Endpoint:
https://plugins.zenuxs.in/api/dataapikey/query

Example:
https://plugins.zenuxs.in/api/dataapikey/query?tag=username&password=pass&apikey=YOUR_API_KEY

---

## 📊 Dashboard

https://plugins.zenuxs.in/advancedAuth/dash

---

## 🛠 Support

https://discord.zenuxs.in  

---

Made with ❤️ by developer.rs (Rishabh)

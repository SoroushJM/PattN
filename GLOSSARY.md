# PattN

PattN manages connection profiles and subscriptions. This glossary distinguishes a profile's connection settings from its display label.

## Language

**Connection profile (کانفیگ)**:
A saved connection definition, including its protocol, endpoint where applicable, credentials, and connection options.
_Avoid_: Server name when referring to the whole profile.

**Display name (نام نمایشی)**:
A user-facing label for a connection profile. Matching labels alone do not establish that two profiles describe the same connection, and different labels alone do not establish different connections.

**Subscription (اشتراک)**:
A configured source or grouping of connection profiles. Two subscriptions may contain profiles describing the same connection.

**Effective connection settings (تنظیمات مؤثر اتصال)**:
The connection settings actually used by the selected core after applying profile values, defaults, and core-specific behavior. Profiles with different saved values can have the same effective connection settings; equivalence can change when defaults or the selected core change.

**Duplicate connection profile (کانفیگ تکراری)**:
A profile describing the same connection as another profile under the selected core and current defaults. Display names and subscription membership alone do not make connections different; different credentials, endpoints, security settings, or request paths can.

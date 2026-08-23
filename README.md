# Silverstripe Gate API

A JWT authenticated content API for the
[SilverGate](https://github.com/atwx/silverstripe-gate-client) modules.

It exists so a central system can read and write content on any managed site
without each site needing its own credentials, its own API tokens, or its own
integration code. The API is deliberately generic: it reflects over the ORM, so
every DataObject a project defines is reachable without writing anything site
specific.

## Two roles, one package

The module adopts whichever role fits what it finds installed alongside it. Both
can be active at once on an install that carries both siblings.

| Installed alongside | Role | What it does |
| --- | --- | --- |
| `atwx/silverstripe-gate-client` | **site** | Answers API calls. Registers `/_silvergateapi` and validates tokens with the client's `TokenService`. |
| `atwx/silverstripe-gate-manager` | **manager** | Makes API calls. Signs a token per `ManagedSite` with that site's own private key and calls its endpoint. |
| neither | none | The module is inert. |

Neither sibling is a hard dependency; the roles are switched on by Silverstripe's
`moduleexists` config rule. That is deliberate — **neither gate-client nor
gate-manager has to change to gain the API.** Both already provide everything
needed: the client validates tokens, and the manager's
`CryptographyService::generateJwt()` already accepts an arbitrary claim payload.

```
                    signs token, calls              validates, executes
 [ gate-manager ] ------------------------> [ gate-client + gate-api ]
 [ + gate-api   ]        HTTPS + JWT              on the managed site
```

## Installation

```bash
composer require atwx/silverstripe-gate-api
```

Install it on the managed sites you want reachable, and on the manager instance
you want to reach them from. It is the same package either way.

### On a managed site

The site needs the SilverGate public key configured, exactly as for gate-client.
If gate-client is already set up, there is nothing more to do — both modules read
the same key, and the API is live as soon as the module is installed.

```yaml
Atwx\SilverGateClient\Services\TokenService:
  public_key: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
```

or via `.env`, with escaped newlines:

```env
SILVERGATECLIENT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

Note that the environment variable wins over the YAML config.

Until a key is configured every request is rejected, so installing the module
does not by itself open anything.

### On the manager

Nothing to configure. `ManagedSite` gains a `callApi()` method and a **Test API**
button in the CMS.

```php
$site = ManagedSite::getByDomain('example.com');

$site->callApi('query', ['class' => 'ScheduleEntry', 'limit' => 5]);

// or through the service, which has convenience wrappers
SiteApiClient::singleton()->create(
    $site,
    'ScheduleEntry',
    ['Title' => 'Welcome', 'Time' => '09:00:00', 'EventDayID' => 5, 'Speakers' => [7, 9]],
    ['sub' => 'content@example.com']
);
```

`create()` and `update()` add `scope: write` for you; everything else defaults to
read.

## Requests

All actions live under `/_silvergateapi/<action>`. Read actions accept GET or
POST, write actions require POST. Parameters go in a JSON body.

```
Authorization: Bearer <jwt>
Content-Type: application/json
```

| Action | Writes | Body |
| --- | --- | --- |
| `ping` | | — |
| `classes` | | `search` |
| `schema` | | `class` |
| `query` | | `class`, `filter`, `sort`, `limit`, `offset`, `stage` |
| `get` | | `class`, `id`, `stage` |
| `create` | ✓ | `class`, `fields` |
| `update` | ✓ | `class`, `id`, `fields` |
| `delete` | ✓ | `class`, `id` |
| `publish` | ✓ | `class`, `id` |
| `unpublish` | ✓ | `class`, `id` |

`class` accepts a fully qualified name or an unambiguous short name.
`filter` takes ORM search filters, e.g. `{"Title:PartialMatch": "news"}`.

### Discovering a site

`classes` lists what is reachable; `schema` describes one class including field
types, the valid values of any Enum, and every relation. Call `schema` before
writing — it is what makes the API usable without knowing the project.

```json
{
  "class": "App\\Models\\ScheduleEntry",
  "versioned": false,
  "fields": [
    {"name": "Title", "type": "Varchar(255)", "label": "Title"},
    {"name": "Time", "type": "Time", "label": "Time"}
  ],
  "relations": {
    "hasOne": [{"name": "EventDay", "field": "EventDayID", "class": "App\\Models\\EventDay"}],
    "manyMany": [{"name": "Speakers", "class": "App\\Models\\Speaker", "through": false}]
  }
}
```

### Writing relations

`has_one` is set through its ID field. `has_many`, `many_many` and
`belongs_many_many` take an array of IDs and replace the whole relation.

```json
{
  "class": "ScheduleEntry",
  "fields": {
    "Title": "Welcome",
    "Time": "09:00:00",
    "EventDayID": 5,
    "Speakers": [7, 9]
  }
}
```

Writing a field the class does not have is an error rather than a silent no-op,
so a typo surfaces immediately.

### Versioned records

Writes always go to the **draft** stage, whatever reading stage the request is
in, and `publish` is a separate call. Reads default to draft; pass
`"stage": "live"` for the published version.

Responses carry `_published` and `_modified` for versioned classes, `_title` for
everything, and `_relations` with the IDs of each multi-value relation on
`get`, `create` and `update`.

## Token claims

The manager signs these alongside the standard `iat` / `exp`. All are optional.

| Claim | Meaning |
| --- | --- |
| `sub` | Email or ID of the member to act as. Defaults to gate-client's configured member. |
| `scope` | `read` (default) or `write`. |
| `classes` | Array of class names this token may touch. |

`CryptographyService::generateJwt()` in gate-manager already accepts a payload
array, so no change is needed there:

```php
$jwt = CryptographyService::singleton()->generateJwt(
    privateKey: $site->PrivateKey,
    payload: ['sub' => 'content@example.com', 'scope' => 'write', 'classes' => ['ScheduleEntry', 'EventDay']],
    issuedAt: time()
);
```

## Restricting access

Four gates apply, narrowest wins.

1. **`denied_classes`** — never reachable. The security tables are denied by
   default; add your own.
2. **`allowed_classes`** — if set, nothing outside the list is reachable.
3. **The token's `classes` claim.**
4. **The model's own `canView()` / `canEdit()` / `canCreate()` / `canDelete()`**,
   evaluated against the member the token acts as.

```yaml
Atwx\SilverGateApi\Site\Services\AccessPolicy:
  allowed_classes:
    - App\Models\ScheduleEntry
    - App\Models\EventDay
    - App\Models\Speaker
```

A class that is out of reach reports the same "unknown class" error as one that
does not exist, so a caller cannot probe for what a site defines.

To refuse writes on a site entirely, regardless of what any token claims:

```yaml
Atwx\SilverGateApi\Site\Services\AuthService:
  allow_writes: false
```

## Notes on security

- The member is set for the request only, via `Security::setCurrentUser()`. No
  session is created and nothing persists between calls.
- Token lifetime is gate-client's `token_max_age_seconds` (60 by default). Sign
  one token per call rather than reusing one.
- gate-client's `login_as_default_admin` defaults to true. If you rely on that
  fallback the API acts as the default admin — give each site a dedicated
  content member and name it in the `sub` claim instead.
- Internal errors return a generic message; the detail is included only on a dev
  site and always goes to the site's logger.
- Responses are sent with `Cache-Control: no-store` and `X-Robots-Tag: noindex`.

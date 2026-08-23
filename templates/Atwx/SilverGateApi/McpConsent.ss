<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Authorise $ClientName</title>
    <style>
        body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #f5f6f8;
               margin: 0; padding: 40px 20px; color: #23262d; }
        .card { max-width: 460px; margin: 0 auto; background: #fff; border-radius: 10px;
                padding: 32px; box-shadow: 0 2px 12px rgb(0 0 0 / 8%); }
        h1 { font-size: 20px; margin: 0 0 6px; }
        .sub { color: #5a6069; font-size: 14px; margin: 0 0 24px; }
        ul { list-style: none; padding: 0; margin: 0 0 24px; }
        li { padding: 10px 0; border-bottom: 1px solid #eceef1; font-size: 14px; }
        li:last-child { border-bottom: 0; }
        .write { color: #a4383a; font-weight: 600; }
        .actions { display: flex; gap: 10px; }
        button { flex: 1; padding: 11px 16px; font-size: 15px; border-radius: 6px;
                 border: 1px solid transparent; cursor: pointer; }
        .approve { background: #1f7a3f; color: #fff; }
        .deny { background: #fff; border-color: #c9ced6; color: #23262d; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorise $ClientName</h1>
        <p class="sub">Signed in as $MemberEmail</p>

        <ul>
            <li>Read content on the sites you may log into</li>
            <% if $RequestsWrite %>
                <li class="write">Create, change and delete content on those sites</li>
            <% else %>
                <li>No write access</li>
            <% end_if %>
        </ul>

        <form method="post" action="$ApproveLink">
            <input type="hidden" name="client_id" value="$ClientId">
            <input type="hidden" name="redirect_uri" value="$RedirectUri">
            <input type="hidden" name="state" value="$State">
            <input type="hidden" name="code_challenge" value="$CodeChallenge">
            <input type="hidden" name="scope" value="$Scope">
            <input type="hidden" name="security_token" value="$SecurityToken">
            <div class="actions">
                <button type="submit" name="deny" value="1" class="deny">Cancel</button>
                <button type="submit" name="approve" value="1" class="approve">Authorise</button>
            </div>
        </form>
    </div>
</body>
</html>

const homeHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Home • Placeholder</title>
    <style>
        :root {
            --bg: #0f172a; /* slate-900 */
            --card: #111827; /* gray-900 */
            --text: #e5e7eb; /* gray-200 */
            --muted: #94a3b8; /* slate-400 */
            --accent: #60a5fa; /* blue-400 */
            --ring: rgba(96,165,250,.35);
        }

        * {
            box-sizing: border-box;
        }

        html, body {
            height: 100%;
        }

        body {
            margin: 0;
            font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
            background: radial-gradient(1000px 600px at 80% -10%, rgba(96,165,250,.12), transparent 60%), radial-gradient(800px 500px at -10% 120%, rgba(16,185,129,.12), transparent 60%), var(--bg);
            color: var(--text);
            display: grid;
            place-items: center;
        }

        .card {
            width: min(640px, 92vw);
            background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
            backdrop-filter: blur(6px);
            border: 1px solid rgba(148,163,184,.18);
            box-shadow: 0 30px 60px rgba(0,0,0,.35);
            border-radius: 20px;
            padding: 28px 28px 22px;
        }

        .logo {
            width: 56px;
            height: 56px;
            border-radius: 14px;
            display: grid;
            place-items: center;
            font-weight: 800;
            letter-spacing: .5px;
            background: linear-gradient(135deg, var(--accent), #22c55e);
            color: #0b1220;
            box-shadow: 0 10px 24px rgba(96,165,250,.28);
            margin-bottom: 14px;
        }

        h1 {
            font-size: clamp(22px, 4vw, 32px);
            margin: 8px 0 6px;
        }

        p {
            margin: 0;
            color: var(--muted);
            line-height: 1.6;
        }

        .actions {
            margin-top: 18px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            appearance: none;
            border: 1px solid rgba(148,163,184,.22);
            background: #0b1220;
            color: var(--text);
            padding: 10px 14px;
            border-radius: 12px;
            cursor: pointer;
            transition: transform .06s ease, box-shadow .2s ease, border-color .2s ease;
            box-shadow: 0 6px 16px rgba(0,0,0,.25);
        }

            .btn:hover {
                transform: translateY(-1px);
                border-color: var(--accent);
                box-shadow: 0 10px 24px rgba(96,165,250,.18);
            }

            .btn.primary {
                background: linear-gradient(135deg, var(--accent), #22c55e);
                color: #0b1220;
                border-color: transparent;
            }

        footer {
            margin-top: 18px;
            font-size: 12px;
            color: var(--muted);
            text-align: center;
        }
    </style>
</head>
<body>
    <main class="card" role="main" aria-labelledby="heading">
        <div class="logo" aria-hidden="true">H</div>
        <h1 id="heading">Home</h1>
        <p>This is a lightweight placeholder. Swap in real content, or keep it as a landing pad while you wire things up.</p>
        <div class="actions">
            <button class="btn primary" onclick="alert('Primary action clicked')">Primary Action</button>
            <button class="btn" onclick="location.reload()">Refresh</button>
            <button class="btn" onclick="document.querySelector('p').textContent='You can edit this later.'">Edit Text</button>
        </div>
        <footer>© <span id="y"></span> • Placeholder</footer>
    </main>
    <script>document.getElementById('y').textContent = new Date().getFullYear();</script>
</body>
</html>

`;

interface AttendanceRequest {
    Event_Id?: number;
    User_Id?: number;
}

interface AttendanceRow {
    Event_Id: number;
    User_Id: number;
}

interface ProfilePicRow {
    ProfilePicture: Uint8Array | null;
}

interface UserRow {
    name: string;
    surname: string;
    userName: string;
    dob: string;
    created_At: string;
    email: string;
    password: string;
}

interface EventRow {
    name: string;
    details: string;
    date: string;
    location: string;
}

interface LoginRequest {
    identifier: string;
    password: string;
}

function toArrayBuffer(str: string): ArrayBuffer {
    return new TextEncoder().encode(str);
}

function toHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Hash with salt using PBKDF2
async function hashPassword(password: string, salt?: Uint8Array) {
    // generate salt if not provided
    if (!salt) salt = crypto.getRandomValues(new Uint8Array(16));

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        toArrayBuffer(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: 100_000,
            hash: "SHA-256",
        },
        keyMaterial,
        256
    );

    const hashHex = toHex(derivedBits);
    return { salt: toHex(salt), hash: hashHex };
}

// Verify password
async function verifyPassword(password: string, saltHex: string, hashHex: string) {
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    const { hash } = await hashPassword(password, salt);
    return hash === hashHex;
}

function sanitizeUser(user: any) {
    const { Password, ...safe } = user; // add any other fields you want hidden
    return safe;
}

const API_KEY: string = "bh3dmUm8wX23mAwiJTdkSBQFFI3jSqk4"

export default {
    async fetch(request: Request, env: any) {
        const key = request.headers.get("x-api-key");
        if (key !== API_KEY) {
            return new Response("Unauthorized", { status: 401 });
        }

        const url = new URL(request.url);
        const method = request.method;

        // Home page
        if (url.pathname === "/") {
            return new Response(homeHTML, {
                headers: { "content-type": "text/html" }
            });
        }

        // Static endpoint: /api/events
        if (url.pathname === "/api/events") {
            if (method === "GET") {
                const { results } = await env.DB.prepare("SELECT * FROM Events").all();
                return Response.json(results);
            }
            if (method === "POST") {
                const postData = await request.json() as EventRow;
                await env.DB.prepare(
                    "INSERT INTO Events (Name, Details, Event_Date, Location) VALUES (?, ?, ?, ?)"
                ).bind(postData.name, postData.details, postData.date, postData.location).run();
                return new Response("Added", { status: 201 });
            }
            return new Response("Method Not Allowed", { status: 405 });
        }

        // static endpoint: /api/users
        if (url.pathname === "/api/users") {
            if (method === "GET") {
                const { results } = await env.DB.prepare("SELECT * FROM Users").all();

                // strip the password from each user
                const safeResults = results.map(sanitizeUser);

                return Response.json(safeResults);
            }
            if (method === "POST") {
                const postData = await request.json() as UserRow;

                // Check if user already exists
                const existingUser = await env.DB.prepare("SELECT * FROM Users WHERE Username = ? OR Email = ?")
                    .bind(postData.userName, postData.email).all();

                if (existingUser.results.length > 0) {
                    return new Response("User already exists", { status: 409 });
                }

                // hash password
                const { salt, hash } = await hashPassword(postData.password);
                // store salt and hash -> password = salt + hash
                postData.password = `${salt}:${hash}`;

                await env.DB.prepare(
                    "INSERT INTO Users (Name, Surname, Username, Dob, Created_At, Email, Password) VALUES (?, ?, ?, ?, ?, ?, ?)"
                ).bind(postData.name, postData.surname, postData.userName, postData.dob, postData.created_At, postData.email, postData.password).run();
                return new Response("Added", { status: 201 });
            }
            return new Response("Method Not Allowed", { status: 405 });
        }

        // static endpoint: /api/login
        if (url.pathname === "/api/login") {
            if (method === "POST") {
                const postData = await request.json() as LoginRequest;
                const field = postData.identifier.includes("@") ? "Email" : "Username";
                const { results } = await env.DB.prepare(`SELECT * FROM Users WHERE ${field} = ?`)
                    .bind(postData.identifier)
                    .all();

                if (!results || results.length === 0)
                    return new Response("Invalid credentials", { status: 401 });

                // Verify password
                const password = results[0]["Password"] as string;
                const [salt, hash] = password.split(":");

                const isValid = await verifyPassword(postData.password, salt, hash);

                if (!isValid) {
                    return new Response("Invalid password", { status: 401 });
                }

                const safeResults = results.map(sanitizeUser);
                return Response.json(safeResults[0]);
            }
            return new Response("Method Not Allowed", { status: 405 });
        }

        // Dynamic endpoints: /api/users/{id}/events
        if (url.pathname.startsWith("/api/users/")) {
            const parts = url.pathname.split("/").filter(Boolean); // ["api", "users", "{id}", "events"]
            const userId = parts[2];

            if (parts[3] === "events") {
                switch (method) {
                    case "GET":
                        const { results } = await env.DB.prepare(
                            "SELECT Event_Id FROM UserEvents WHERE User_Id = ?"
                        ).bind(userId).all() as { results: AttendanceRow[] };
                        return Response.json({ eventIds: results.map(r => r.Event_Id) });

                    case "POST":
                        const postData = await request.json() as AttendanceRequest;
                        await env.DB.prepare(
                            "INSERT INTO UserEvents (User_ID, Event_ID) VALUES (?, ?)"
                        ).bind(userId, postData.Event_Id).run();
                        return new Response("Added", { status: 201 });

                    case "DELETE":
                        const eventId = parts[4]; // /api/users/{id}/events/{eventId}
                        await env.DB.prepare(
                            "DELETE FROM UserEvents WHERE User_Id = ? AND Event_Id = ?"
                        ).bind(userId, eventId).run();
                        return new Response("Removed", { status: 200 });

                    default:
                        return new Response("Method Not Allowed", { status: 405 });
                }
            }

            if (parts[3] === "profilepicture")
            {
                switch (method) {
                    case "GET":
                        const { results } = await env.DB.prepare(
                            "SELECT ProfilePicture FROM Users_AdditionalInfo WHERE User_Id = ?"
                        ).bind(userId).all();

                        if (results.length === 0) {
                            return new Response("Not found", { status: 404 });
                        }

                        const blobData = results[0].data as Uint8Array;

                        // Convert it to ArrayBuffer if you need a Response object
                        const picarrayBuffer = blobData.slice(
                            blobData.byteOffset,
                            blobData.byteOffset + blobData.byteLength
                        );

                        return new Response(picarrayBuffer, {
                            headers: {
                                "Content-Type": "image/png", // or whatever type you stored
                            },
                        });


                    case "POST":
                        // Read the bytes directly from the request
                        const arrayBuffer = await request.arrayBuffer();
                        const bytes = new Uint8Array(arrayBuffer);

                        // Store in DB
                        await env.DB.prepare(
                            "INSERT INTO Users_AdditionalInfo (User_Id, ProfilePicture) VALUES(?, ?) ON CONFLICT(User_Id) DO UPDATE SET ProfilePicture = excluded.ProfilePicture; "
                        ).bind(userId, bytes).run()
                        return new Response("OK", { status: 201 });

                    default:
                        return new Response("Method Not Allowed", { status: 405 });
                }
            }

            if (!parts[3]) {
                switch (method) {
                    case "GET":
                        const { results } = await env.DB.prepare(
                            "SELECT * FROM Users WHERE User_Id = ?"
                        ).bind(userId).all();

                        if (!results || results.length === 0) return new Response("User not found", { status: 404 });

                        // strip the password from each user
                        const safeResults = results.map(sanitizeUser);

                        return Response.json(safeResults[0]);

                    case "DELETE":
                        await env.DB.prepare(
                            "DELETE FROM Users WHERE User_Id = ?"
                        ).bind(userId).run();
                        return new Response("Deleted", { status: 200 });

                    default:
                        return new Response("Method Not Allowed", { status: 405 });
                }
            }
        }

        // Dynamic endpoints: /api/events/{id}/users
        if (url.pathname.startsWith("/api/events/")) {
            const parts = url.pathname.split("/").filter(Boolean); // ["api", "events", "{id}", "users"]
            const eventId = parts[2];

            if (parts[3] === "users") {
                switch (method) {
                    case "GET":
                        const { results } = await env.DB.prepare(
                            "SELECT User_Id FROM UserEvents WHERE Event_Id = ?"
                        ).bind(eventId).all() as { results: AttendanceRow[] };
                        return Response.json({ userIds: results.map(r => r.User_Id) });

                    case "DELETE":
                        const userId = parts[4]; // /api/events/{id}/users/{userid}
                        await env.DB.prepare(
                            "DELETE FROM UserEvents WHERE User_Id = ? AND Event_Id = ?"
                        ).bind(eventId, userId).run();
                        return new Response("Removed", { status: 200 });

                    default:
                        return new Response("Method Not Allowed", { status: 405 });
                }
            }

            if (!parts[3]) {
                switch (method) {
                    case "GET":
                        const { results } = await env.DB.prepare(
                            "SELECT * FROM Events WHERE Event_Id = ?"
                        ).bind(eventId).all();

                        if (results.length === 0) return new Response("Event not found", { status: 404 });
                        return Response.json(results[0]);

                    case "POST":
                        const postData = await request.json() as EventRow;
                        await env.DB.prepare(
                            "INSERT INTO Events (Name, Details, Event_Date, Location) VALUES (?, ?, ?, ?)"
                        ).bind(postData.name, postData.details, postData.date, postData.location).run();
                        return new Response("Added", { status: 201 });

                    case "DELETE":
                        await env.DB.prepare(
                            "DELETE FROM Events WHERE Event_Id = ?"
                        ).bind(eventId).run();
                        return new Response("Deleted", { status: 200 });

                    default:
                        return new Response("Method Not Allowed", { status: 405 });
                }
            }
        }

        // Not found fallback
        return new Response("Not Found", { status: 404 });
    },
} satisfies ExportedHandler<Env>;

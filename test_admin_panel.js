const jwt = require('jsonwebtoken');
require('dotenv').config();

// We are acting as the client, but we'll manually forge a valid JWT for testing 
// since we don't have the user's TOTP Authenticator code.
const token = jwt.sign(
    { userId: 1, email: "[EMAIL_ADDRESS]", mfaVerified: true },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
);

async function testAdmin() {
    console.log("=== Testing Admin Panel API ===");
    console.log("Using Token for User ID 1 (Admin)\n");

    try {
        // 1. Test fetching ABAC Policies (Requires Admin Role)
        console.log("Fetching active ABAC Policies...");
        const res1 = await fetch('http://127.0.0.1:5000/api/admin/policies/abac', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const res1Text = await res1.text();
        console.log("HTTP Status:", res1.status);
        try {
            const data1 = JSON.parse(res1Text);
            if (res1.ok) {
                console.log("SUCCESS! Retrieved Policies:");
                data1.forEach(p => console.log(`- ${p.name} (${p.effect})`));
            } else {
                console.error("FAILED to retrieve policies:", data1);
            }
        } catch (e) {
            console.error("Failed to parse JSON. Raw response:", res1Text.substring(0, 200));
        }

        console.log("\n-----------------------------------\n");

        // 2. Test assigning a role
        console.log("Assigning 'editor' role to User ID 2...");
        const res2 = await fetch('http://127.0.0.1:5000/api/admin/users/2/role', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ role: 'editor' })
        });

        const data2 = await res2.json();
        if (res2.ok) {
            console.log("SUCCESS! Server Response:", data2.msg);
        } else {
            console.error("FAILED to assign role:", data2);
        }

    } catch (error) {
        console.error("Test execution failed:", error);
    }
}

testAdmin();

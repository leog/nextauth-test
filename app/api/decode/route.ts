import { decode } from "@auth/core/jwt"; // or 'next-auth/jwt' for v4

async function decodeSecureState(token: string) {
  const decoded = await decode({
    token: token,
    secret: process.env.AUTH_SECRET as string, // Use the same secret as your app
    salt: "__Secure-authjs.state",
  });
  return decoded; // Returns the decrypted JSON payload
}

export async function handler(req: Request): Promise<Response> {
  try {
    const { searchParams } = new URL(req.url);
    const stateToken = searchParams.get("state");

    if (!stateToken) {
      return new Response("Missing state token", { status: 400 });
    }

    const decodedState = await decodeSecureState(stateToken);

    if (!decodedState) {
      return new Response("Invalid or expired state token", { status: 400 });
    }

    return new Response(JSON.stringify(decodedState), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response("Internal Server Error: " + (e as Error).message, {
      status: 500,
    });
  }
}

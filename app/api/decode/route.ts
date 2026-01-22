import { decode } from "@auth/core/jwt";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

async function decodeSecureState(token: string) {
  const decoded = await decode({
    token: token,
    secret: process.env.AUTH_SECRET as string, // Use the same secret as your app
    salt: "__Secure-authjs.state",
  });
  return decoded; // Returns the decrypted JSON payload
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const stateToken = searchParams.get("state");

    if (!stateToken) {
      return new NextResponse("Missing state token", { status: 400 });
    }

    const decodedState = await decodeSecureState(stateToken);

    if (!decodedState) {
      return new NextResponse("Invalid or expired state token", { status: 400 });
    }

    return NextResponse.json(decodedState, { status: 200 });
  } catch (e) {
    return new NextResponse(
      "Internal Server Error: " + (e as Error).message,
      { status: 500 },
    );
  }
}

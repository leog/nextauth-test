import { decode } from "@auth/core/jwt";
import type { NextApiRequest, NextApiResponse } from "next";

async function decodeSecureState(token: string) {
  const decoded = await decode({
    token: token,
    secret: process.env.AUTH_SECRET as string, // Use the same secret as your app
    salt: "__Secure-authjs.state",
  });
  return decoded; // Returns the decrypted JSON payload
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  try {
    const { searchParams } = new URL(req.url || "");
    const stateToken = searchParams.get("state");

    if (!stateToken) {
      return res.status(400).send("Missing state token");
    }

    const decodedState = await decodeSecureState(stateToken);

    if (!decodedState) {
      return res.status(400).send("Invalid or expired state token");
    }

    return res.status(200).json(decodedState);
  } catch (e) {
    return res
      .status(500)
      .send("Internal Server Error: " + (e as Error).message);
  }
}

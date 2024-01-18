import prisma from '@typebot.io/lib/prisma'
import { getAuthOptions } from '@/pages/api/auth/[...nextauth]'
import * as Sentry from '@sentry/nextjs'
import { User } from '@typebot.io/prisma'
import { NextApiRequest, NextApiResponse } from 'next'
import { getServerSession } from 'next-auth'
import { env } from '@typebot.io/env'
import { mockedUser } from '@typebot.io/lib/mockedUser'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'
import util from 'util'

interface Header {
  kid: string
}

interface Key {
  publicKey?: string
  rsaPublicKey?: string
}

type Callback = (err: Error | null, signingKey?: string) => void

// Initialize JWKS client
const client = jwksClient({
  jwksUri: `https://${env.AUTH0_DOMAIN}/.well-known/jwks.json`,
})

// Function to retrieve signing key
function getKey(header: Header, callback: Callback): void {
  client.getSigningKey(header.kid, function (err: Error | null, key?: Key) {
    const signingKey = key?.publicKey || key?.rsaPublicKey
    callback(null, signingKey)
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const verify: any = util.promisify(jwt.verify)

export const getAuthenticatedUser = async (
  req: NextApiRequest,
  res: NextApiResponse
): Promise<User | undefined> => {
  const bearerToken = extractBearerToken(req)
  if (bearerToken) return authenticateByToken(bearerToken)
  const user = env.NEXT_PUBLIC_E2E_TEST
    ? mockedUser
    : ((await getServerSession(req, res, getAuthOptions({})))?.user as
        | User
        | undefined)
  if (!user || !('id' in user)) return
  Sentry.setUser({ id: user.id })
  return user
}

const authenticateByToken = async (
  apiToken: string
): Promise<User | undefined> => {
  if (typeof window !== 'undefined') return
  let user: User | undefined
  user = (await prisma.user.findFirst({
    where: { apiTokens: { some: { token: apiToken } } },
  })) as User

  // Verify token against Auth0
  if (!user) {
    const { email } = await verify(apiToken, getKey, { algorithms: ['RS256'] })
    user = (await prisma.user.findFirst({
      where: { email },
    })) as User
  }
  Sentry.setUser({ id: user.id })
  return user
}

const extractBearerToken = (req: NextApiRequest) =>
  req.headers['authorization']?.slice(7)

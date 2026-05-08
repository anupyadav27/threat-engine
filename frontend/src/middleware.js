import { NextResponse } from 'next/server';

export function middleware(request) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get('access_token')?.value;
  console.log('[mw]', pathname, 'bypass=', process.env.LOCAL_DEV_BYPASS_AUTH, 'pub=', process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH);

  // LOCAL_DEV_BYPASS_AUTH=1 — skip auth middleware entirely (local dev only).
  // The local gateway synthesizes X-Auth-Context, so no real cookie is needed.
  if (
    process.env.LOCAL_DEV_BYPASS_AUTH === '1' ||
    process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH === '1'
  ) {
    return NextResponse.next();
  }

  // Not authenticated → redirect to login (clone preserves basePath)
  if (!token) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/auth/login';
    loginUrl.searchParams.set('next', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // New SSO user → redirect to getting-started wizard
  const needsOnboarding = request.cookies.get('onboarding_pending')?.value === '1';
  if (
    needsOnboarding &&
    pathname !== '/onboarding/getting-started' &&
    !pathname.startsWith('/api/')
  ) {
    const wizardUrl = request.nextUrl.clone();
    wizardUrl.pathname = '/onboarding/getting-started';
    return NextResponse.redirect(wizardUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!auth|api|_next/static|_next/image|favicon\\.ico|public).*)',
  ],
};

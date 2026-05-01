import { NextResponse } from 'next/server';

export function middleware(request) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get('access_token')?.value;

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

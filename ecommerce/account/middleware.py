from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse

class BlacklistTokenMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth = JWTAuthentication()
        header = auth.get_header(request)
        
        if header:
            try:
                raw_token = auth.get_raw_token(header)
                access_token = AccessToken(raw_token)

                # Get the JTI (unique identifier) of the access token
                jti = access_token['jti']

                # Check if the corresponding refresh token is blacklisted
                if BlacklistedToken.objects.filter(token__jti=jti).exists():
                    return JsonResponse({'message': 'Session expired. Please log in again.'}, status=401)
            except Exception:
                return JsonResponse({'message': 'Invalid token. Please log in again.'}, status=401)

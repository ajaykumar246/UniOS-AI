from supabase import create_client, Client
from app.core.config import settings

# Client for user operations (uses anon key)
supabase_client: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)

# Admin client for service operations (uses service role key)
supabase_admin: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

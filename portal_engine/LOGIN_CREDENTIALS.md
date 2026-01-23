# CSPM Login Credentials

## 🌐 Frontend UI

**URL:**
```
http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
```

## 🔐 Login Credentials

**Email:** `ayushajha11@gmail.com`  
**Password:** `Ayush@6112`

**User Details:**
- First Name: Ayush
- Last Name: Jha
- Role: Superuser / Admin
- Status: Active

## ✅ User Created

The user has been created in the PostgreSQL database with:
- Email: ayushajha11@gmail.com
- Password: Ayush@6112 (hashed)
- Superuser privileges
- Active status

## 📝 How to Login

1. Open the Frontend UI:
   ```
   http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
   ```

2. Enter credentials:
   - **Email:** `ayushajha11@gmail.com`
   - **Password:** `Ayush@6112`

3. Click "Login" or "Sign In"

## 🔧 If Login Fails

### Option 1: Verify User Exists
```bash
kubectl exec -n cspm deployment/django-backend -- \
  python manage.py shell -c \
  "from user_auth.models import Users; print(Users.objects.filter(email='ayushajha11@gmail.com').exists())"
```

### Option 2: Reset Password
```bash
kubectl exec -n cspm deployment/django-backend -- \
  python manage.py shell -c \
  "from user_auth.models import Users; \
   u = Users.objects.get(email='ayushajha11@gmail.com'); \
   u.set_password('Ayush@6112'); \
   u.save(); \
   print('Password reset!')"
```

### Option 3: Create Additional Users
```bash
kubectl exec -it -n cspm deployment/django-backend -- \
  python manage.py createsuperuser
```

## 🔍 Troubleshooting

### Check Backend Connectivity

The frontend UI needs to connect to the backend APIs. If login fails, check:

1. **Frontend can reach backend:**
   - Open browser console (F12)
   - Look for API call errors
   - Check if frontend is configured with correct backend URLs

2. **Backend is responding:**
   ```bash
   # Test login endpoint
   curl -X POST http://ac2b6937e3cbc4e499e82a26ea72c642-1571994199.ap-south-1.elb.amazonaws.com/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "ayushajha11@gmail.com", "password": "Ayush@6112"}'
   ```

3. **CORS is configured:**
   - Frontend UI needs to be in ALLOWED_HOSTS
   - May need to update CORS settings in Django

### Check Frontend Configuration

The frontend might be hardcoded to connect to different backend URLs. Check frontend environment variables or configuration files.

## 📊 System Status

- ✅ Frontend UI: Running (cspm-ui namespace)
- ✅ Django Backend: Running (cspm namespace)
- ✅ Onboarding API: Running (cspm namespace)
- ✅ Scheduler: Running (cspm namespace)
- ✅ Database: Connected (PostgreSQL RDS)
- ✅ First User: Created in database

## 🎯 Summary

**Everything is deployed and ready!**

1. Open: http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com
2. Login with: ayushajha11@gmail.com / Ayush@6112
3. Start using CSPM!

If you encounter any issues, check the troubleshooting section above.

---
**Last Updated:** 2026-01-16 21:17


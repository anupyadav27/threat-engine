# Azure Compliance Engine - Quick Start

## 🚀 Current Status

**Phase:** Ready for testing  
**Services:** 58 Azure services mapped  
**Rules:** 1,686 compliance rules  
**Architecture:** Hybrid (service-based + client pooling)

---

## 📦 Installation

```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Install all Azure SDK packages (~5 min, 45+ packages)
pip3 install -r requirements.txt
```

---

## 🔑 Configuration

```bash
# Required
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Optional (for service principal)
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

---

## ✅ Test Components

```bash
# 1. Test service registry
python3 engine/service_registry.py

# 2. Test client manager (requires Azure credentials)
python3 engine/azure_client_manager.py

# 3. Test hybrid architecture
python3 test_hybrid_architecture.py

# 4. Run compliance engine
python3 run_engine.py --service compute
```

---

## 📊 Architecture

**Hybrid Approach:**
- Service-based folders (user-friendly)
- Client pooling by package (efficient)
- 12% performance gain

**Key Files:**
- `engine/service_registry.py` - Service → Package mapping
- `engine/azure_client_manager.py` - Client pooling
- `AZURE_SERVICE_PACKAGE_MAPPING.csv` - Service data

---

## 📚 Reference

- **Azure SDK Docs:** https://docs.microsoft.com/python/azure/
- **All Services:** See `AZURE_SERVICE_PACKAGE_MAPPING.csv`
- **Detailed Docs:** In `_archive/docs/`

---

_Last Updated: December 2, 2025_


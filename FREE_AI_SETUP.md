# 🆓 FREE AI SETUP GUIDE - Google Gemini

## ✅ **NO CREDIT CARD REQUIRED!**

Your ThreatHunter AI now uses **Google Gemini** - completely FREE with 1500+ requests per day!

---

## 🔑 **GET YOUR FREE API KEY (2 MINUTES)**

### **Step 1: Visit Google AI Studio**
```
🌐 https://aistudio.google.com/app/apikey
```

### **Step 2: Sign In**
- Use your existing Google account (Gmail)
- No sign-up needed if you have Gmail!

### **Step 3: Create API Key**
1. Click **"Create API Key"**
2. Select **"Create API key in new project"** (or use existing)
3. Copy the key (starts with `AIza...`)

**Example:**
```
AIzaSyDq1a2b3c4d5e6f7g8h9i0jklmnopqrstu
```

⚠️ **Save it somewhere safe!**

---

## 🚀 **ADD TO RENDER (DEPLOYMENT)**

When deploying on Render, add this environment variable:

### **Environment Variables:**

| Key | Value |
|-----|-------|
| `GEMINI_API_KEY` | `AIzaSyD...your-key-here` |
| `FLASK_ENV` | `production` |
| `PORT` | `10000` |
| `PYTHONUNBUFFERED` | `1` |

---

## 💻 **TEST LOCALLY (OPTIONAL)**

Want to test before deploying?

### **Windows:**
```bash
cd C:\Users\visha\Desktop\threathunter-ai-complete

# Set environment variable
set GEMINI_API_KEY=AIzaSyD...your-key-here

# Install dependencies
pip install -r requirements.txt

# Run server
python threathunter_backend.py

# Open browser
# http://localhost:5000
```

### **Mac/Linux:**
```bash
cd threathunter-ai-complete/

# Set environment variable
export GEMINI_API_KEY=AIzaSyD...your-key-here

# Install dependencies
pip install -r requirements.txt

# Run server
python threathunter_backend.py

# Open browser
# http://localhost:5000
```

---

## 🎯 **WHAT YOU GET (100% FREE)**

### **Google Gemini 1.5 Flash:**
- ✅ **1,500 requests per day FREE**
- ✅ **15 requests per minute**
- ✅ **No credit card required**
- ✅ **Comparable to GPT-4 quality**
- ✅ **Fast responses (< 2 seconds)**

### **Your AI Analysis:**
Every threat will include:
```
🤖 AI Threat Analysis (Powered by Gemini - FREE)

Impact Assessment:
Attacker attempting to extract credentials from LSASS memory,
indicating advanced persistent threat with domain admin access goals.

Attack Context:
Using Mimikatz or similar tools to harvest plaintext passwords and
NTLM hashes for lateral movement across the network.

Immediate Actions:
• Isolate affected host immediately from network
• Reset all domain administrator passwords
• Enable Credential Guard on all Windows endpoints

Risk Level: CRITICAL
Attacker has demonstrated privilege escalation capability and
likely has persistence mechanisms in place.
```

---

## 📊 **USAGE LIMITS (FREE TIER)**

| Feature | Limit |
|---------|-------|
| Requests per day | 1,500 (FREE) |
| Requests per minute | 15 |
| Input tokens | 1M per request |
| Output tokens | 8K per request |
| Cost | **$0.00** |

**For your demo:** 1,500 requests = analyzing ~750 log files per day!

---

## 🆚 **FREE AI COMPARISON**

| Provider | Cost | Requests/Day | Quality | Speed |
|----------|------|--------------|---------|-------|
| **Google Gemini** | FREE | 1,500 | ⭐⭐⭐⭐⭐ | Fast |
| OpenAI GPT-4 | $$$$ | Paid only | ⭐⭐⭐⭐⭐ | Fast |
| OpenAI GPT-3.5 | $ | 3/min free | ⭐⭐⭐⭐ | Fast |
| Hugging Face | FREE | Unlimited | ⭐⭐⭐ | Slow |

**Winner:** Google Gemini (best quality + completely free!)

---

## ⚡ **QUICK START CHECKLIST**

- [ ] Get API key from https://aistudio.google.com/app/apikey
- [ ] Copy the key (starts with `AIza...`)
- [ ] Add `GEMINI_API_KEY` to Render environment variables
- [ ] Deploy on Render
- [ ] Test with sample log file
- [ ] See AI analysis appear! 🎉

---

## 🔒 **SECURITY NOTES**

✅ **DO:**
- Store key in environment variables
- Keep key private
- Use in server-side code only

❌ **DON'T:**
- Commit key to GitHub
- Expose key in HTML/JavaScript
- Share your API key publicly

---

## 🐛 **TROUBLESHOOTING**

### **Issue: "AI analysis disabled"**
**Solution:** 
1. Check environment variable is set: `GEMINI_API_KEY`
2. Verify key starts with `AIza`
3. Restart your server

### **Issue: "API key not valid"**
**Solution:**
1. Go back to https://aistudio.google.com/app/apikey
2. Click "Create API Key" again
3. Copy the NEW key
4. Update environment variable

### **Issue: "Rate limit exceeded"**
**Solution:**
- You've used 1,500 requests today
- Wait 24 hours for reset
- Or upgrade to paid tier (optional)

---

## 📈 **UPGRADE OPTIONS (OPTIONAL)**

If you need more requests later:

| Plan | Requests/Day | Cost |
|------|--------------|------|
| Free | 1,500 | $0 |
| Pay-as-you-go | Unlimited | $0.35 per 1M tokens |

**For demo/portfolio:** FREE tier is MORE than enough! 🎉

---

## 🎓 **LEARNING RESOURCES**

Want to learn more about Gemini?

- 📚 Documentation: https://ai.google.dev/docs
- 🎮 Playground: https://aistudio.google.com
- 💬 Community: https://developers.googleblog.com

---

## ✅ **YOU'RE READY!**

Your ThreatHunter AI now has:
- ✅ FREE AI analysis (Google Gemini)
- ✅ 1,500 requests per day
- ✅ GPT-4 level quality
- ✅ No credit card needed
- ✅ Production-ready code

**Next step:** Deploy on Render and add your API key! 🚀

---

**Questions?** Just ask! I'm here to help! 💪

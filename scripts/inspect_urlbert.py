import time
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_ID = "CrabInHoney/urlbert-tiny-v4-malicious-url-classifier"

print(f"Loading {MODEL_ID}...")
t0 = time.perf_counter()
try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    load_time = time.perf_counter() - t0
    print(f"Model loaded successfully in {load_time:.2f}s!")
    print(f"Config id2label: {model.config.id2label}")
    print(f"Config label2id: {model.config.label2id}")
    print(f"Num labels: {model.config.num_labels}")
    print(f"Architecture: {model.__class__.__name__}")
    
    test_urls = [
        "https://www.google.com",
        "http://secure-sbi-kyc-update.xyz/login.php",
        "https://github.com/torvalds/linux",
        "http://paypal-security-update-account-verification.com/login"
    ]
    
    model.eval()
    for u in test_urls:
        t_inf0 = time.perf_counter()
        inputs = tokenizer(u, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)[0].tolist()
        inf_time = (time.perf_counter() - t_inf0) * 1000
        label_probs = {model.config.id2label[i]: round(probs[i], 4) for i in range(len(probs))}
        pred_idx = int(torch.argmax(logits, dim=-1).item())
        pred_label = model.config.id2label[pred_idx]
        print(f"\nURL: {u}")
        print(f"Predicted: {pred_label} (latency: {inf_time:.1f}ms)")
        print(f"Probabilities: {label_probs}")
except Exception as e:
    print(f"Error loading model: {type(e).__name__}: {e}")

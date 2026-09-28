# 🎬 SecureShield AI: Live Demo Script

**Total Estimated Duration**: ~3 minutes

## Scene 1: Introduction (0:00 - 0:30)
**Presenter**: "Welcome to SecureShield AI, an intelligent mobile platform designed to protect users from modern phishing, malware, and social engineering attacks across SMS, Social Media, and Email."
*Show the architecture diagram*
**Presenter**: "Today, we'll demonstrate our unified threat engine analyzing live data using three input flows: a shared link, a shared file, and an automated background Gmail sweep."

---

## Scene 2: The E-Commerce Scam (0:30 - 1:15)
*Action: On the Android Emulator, open the SMS/Messages app. Show a fake message: "Amazon: Your account is locked! Verify identity here: `http://192.168.1.1@secure-login-verify.xyz/account`"*

**Presenter**: "Here is a classic phishing text targeting your Amazon account. Users don't need to copy/paste; they just use the native Android Share menu."
*Action: Tap and hold the message -> Share -> Select 'SecureShield AI'*

**Presenter**: "The text and URL are instantly routed to our backend `/analyze/message` endpoint. Our lexical heuristic engine spots the injected credentials (the `@` symbol in the URL) and the IP-based host routing, while the NLP engine catches the urgent language ('locked')."

*Action: Show the Android Screen pop up with a red 'Deceptive/Phishing' badge, Score: 85/100, and the plain-language reason list.*
**Presenter**: "The fusion engine aggregates these red flags, bypassing typical default responses, and gives clear instructions to the user: 'Block this sender and delete the message.'"

---

## Scene 3: The Trojan Invoice (1:15 - 2:00)
*Action: Open the Android File Manager. Long press on a file named `invoice.exe` -> Share -> SecureShield AI.*

**Presenter**: "Next, imagine a user downloads an email attachment. We don't want them opening it blindly. SecureShield reads the file bytes locally and streams it via multipart request strictly matching our 10MB memory limit."

*Action: Watch the UI update to a loading spinner, then pop a red 'Malware' badge.*
**Presenter**: "Our Magic Bytes preprocessing caught that this file was lying about its extension, and our VirusTotal hash engine confirmed a threat. If a user tries sharing a 2 GB movie file later, our app won't crash—it throws a native safeguard preventing an out-of-memory exception."

---

## Scene 4: Seamless Gmail integration (2:00 - 2:40)
*Action: Open the SecureShield app natively. Tap "Connect Gmail & Scan Inbox".*

**Presenter**: "Users don't always manually share things. Here, SecureShield securely requests `gmail.readonly` OAuth access. Once approved, the device fetches the latest unread email containing urgent refund language."

*Action: UI pops a 'Phishing (Email)' badge with the Sender's email address labeled 'Target'.*
**Presenter**: "Not only did our NLP spot the phishing template, our SQLite 'Sender Behavior' engine realized this contact had never sent a link before, giving it an 'Out-of-character' anomaly flag—even if the sender is completely unknown."

---

## Scene 5: Feedback & Model Retuning Loop (2:40 - 3:00)
*Action: At the bottom of the Email screen, click the '👎 Inaccurate' button.*

**Presenter**: "No AI is perfect. Users can submit thumbs up/down feedback directly on the results. This doesn't vanish—it syncs directly back to our backend `feedback.db` SQLite table, attaching the target, category, and score."
**Presenter**: "In future phases, our retraining pipeline will automatically comb this database to organically alter the fusion confidence weights! Thank you for watching."

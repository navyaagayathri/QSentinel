Q-SENTINEL
Eavesdropper-Aware BB84 Quantum Key Distribution for Secure Defence Communication
=================================================================================

WHAT IT IS
  A Java (Swing) simulator of a complete Quantum Key Distribution (QKD) link:
  BB84 photon exchange -> HMAC-authenticated classical channel -> sifting + QBER eavesdropper
  detection -> error correction -> SHA-256 privacy amplification -> AES-256-GCM messaging,
  plus an eavesdropper analysis chart, a Diffie-Hellman break demo and a hash-chained session log.

REQUIREMENTS
  JDK 11 or newer (you already have it).  Check with:  java -version

HOW TO RUN  (any ONE of these)
  1. Terminal:   cd Q-Sentinel folder   then   java QSentinel.java
  2. Mac/Linux:  ./run.sh
  3. Windows:    double-click run.bat
  4. VS Code:    open this folder, open QSentinel.java, click "Run" above main().
  Keep the folder structure as it is (the program reads sample_data/messages.txt if present).

3-MINUTE DEMO
  Tab 1  BB84 Key Exchange : click "Demo 1: Secure line"  -> KEY ACCEPTED
                             click "Demo 2: Eavesdropper" -> QBER ~25% -> ABORTED
                             click "Demo 3: MITM"         -> HMAC fails  -> ABORTED
  Tab 2  Secure Messaging  : (after Demo 1) ENCRYPT & SEND. Eve fails to decrypt. Tick
                             "modifies ciphertext in transit" -> Bob rejects it.
  Tab 3  Analysis          : "Run experiment" -> QBER vs Eve's activity, crossing the 11% line.
  Tab 4  Classical vs Quantum : "Eve attacks Diffie-Hellman" -> small DH broken in milliseconds.
  Tab 5  Session Log       : every run is hash-chained; "Tamper" turns the chain red.
  Top right: Light / Dark mode.

FOLDER
  QSentinel.java          the complete program (single file)
  run.sh / run.bat        launchers
  sample_data/            messages.txt (sample messages), qber_experiment.csv, sample_session_log.csv
  screenshots/            output screenshots for your report / PPT
  docs/Project_Details.md title, abstract, existing vs proposed, CO/PO mapping, viva Q&A

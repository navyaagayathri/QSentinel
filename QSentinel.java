import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.List;

/**
 * Q-Sentinel: Eavesdropper-Aware BB84 Quantum Key Distribution for Secure Defence Communication.
 *
 * Pipeline (as in real QKD systems such as the ones DRDO is trialling):
 *   1. BB84 photon exchange (Alice -> [Eve?] -> Bob), random bases, noisy channel
 *   2. Classical channel authenticated with HMAC-SHA256 (pre-shared key) -> blocks man-in-the-middle
 *   3. Sifting (keep matching bases) + QBER estimation on a public sample -> eavesdropper detection
 *   4. Error correction (Cascade-style parity search) + key confirmation
 *   5. Privacy amplification (SHA-256) -> 256-bit key
 *   6. AES-256-GCM encrypted messaging with that key
 * Extras: eavesdropping analysis chart, classical Diffie-Hellman break demo (why QKD), SHA-256 hash-chained session log.
 *
 * Run: java QSentinel.java      (JDK 11+)
 */
public class QSentinel {

    // ===================== CONSTANTS =====================
    static final SecureRandom RNG = new SecureRandom();
    static final double QBER_LIMIT = 0.11;   // standard BB84 tolerance
    static final double EC_EFF = 1.05;       // error-correction efficiency (Cascade ~1.05)
    static final int KEY_BITS = 256;
    static final byte[] PSK = new byte[32];  // pre-shared authentication key (loaded in both units)
    static { RNG.nextBytes(PSK); }

    // ===================== CRYPTO HELPERS =====================
    static byte[] sha256b(byte[] d) {
        try { return MessageDigest.getInstance("SHA-256").digest(d); } catch (Exception e) { throw new RuntimeException(e); }
    }
    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static String sha256(String s) { return hex(sha256b(s.getBytes(StandardCharsets.UTF_8))); }
    static byte[] hmac(byte[] k, byte[] d) {
        try { Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(k, "HmacSHA256")); return m.doFinal(d); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static byte[] pack(int[] bits) {
        byte[] out = new byte[(bits.length + 7) / 8];
        for (int i = 0; i < bits.length; i++) if (bits[i] == 1) out[i / 8] |= (byte) (1 << (i % 8));
        return out;
    }
    static byte[] toBytes(int[] x) { byte[] b = new byte[x.length]; for (int i = 0; i < x.length; i++) b[i] = (byte) x[i]; return b; }
    static byte[] aes(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        return c.doFinal(data);
    }
    static double h2(double p) {
        if (p <= 0 || p >= 1) return 0;
        return -p * Math.log(p) / Math.log(2) - (1 - p) * Math.log(1 - p) / Math.log(2);
    }
    static String now() { return new java.text.SimpleDateFormat("HH:mm:ss").format(new Date()); }

    // ===================== BB84 SIMULATION =====================
    static class Session {
        int n, intercepted, sifted, sample, sampleErr, raw, secureLen;
        double eveFrac, noise, qber = -1, eveKnows = -1;
        boolean mitm, authOK = true, accepted;
        int[] aBit, aBasis, bBasis, bBit, eBasis, eBit;
        boolean[] kept, sampled;
        String decision = "", reason = "", fp = "-";
        byte[] key, eveKey;
    }

    /** Photon transmission: Alice prepares, Eve may intercept-resend, channel noise, Bob measures. */
    static void simulate(Session s) {
        int n = s.n;
        s.aBit = new int[n]; s.aBasis = new int[n]; s.bBasis = new int[n]; s.bBit = new int[n];
        s.eBasis = new int[n]; s.eBit = new int[n];
        for (int i = 0; i < n; i++) {
            s.aBit[i] = RNG.nextInt(2); s.aBasis[i] = RNG.nextInt(2);
            int pBit = s.aBit[i], pBasis = s.aBasis[i];            // the photon state in flight
            s.eBasis[i] = -1;
            if (RNG.nextDouble() < s.eveFrac) {                    // intercept-resend attack
                int eb = RNG.nextInt(2);
                int m = (eb == pBasis) ? pBit : RNG.nextInt(2);    // wrong basis => random outcome
                s.eBasis[i] = eb; s.eBit[i] = m; pBit = m; pBasis = eb; s.intercepted++;
            }
            s.bBasis[i] = RNG.nextInt(2);
            int meas = (s.bBasis[i] == pBasis) ? pBit : RNG.nextInt(2);
            if (RNG.nextDouble() < s.noise) meas ^= 1;             // channel noise
            s.bBit[i] = meas;
        }
        s.kept = new boolean[n];
        for (int i = 0; i < n; i++) if (s.aBasis[i] == s.bBasis[i]) { s.kept[i] = true; s.sifted++; }
    }

    static Session run(int n, double eveFrac, double noise, boolean mitm) {
        Session s = new Session();
        s.n = n; s.eveFrac = eveFrac; s.noise = noise; s.mitm = mitm;
        simulate(s);
        // --- authenticated classical channel: Alice's basis announcement carries an HMAC tag ---
        byte[] ab = toBytes(s.aBasis);
        byte[] tag = hmac(PSK, ab);
        byte[] rx = ab.clone();
        if (mitm) rx[RNG.nextInt(n)] ^= 1;                         // attacker alters the announcement
        s.authOK = MessageDigest.isEqual(tag, hmac(PSK, rx));
        if (!s.authOK) {
            s.decision = "ABORTED";
            s.reason = "HMAC-SHA256 check of the classical channel FAILED (announcement was modified: man-in-the-middle).";
            return s;
        }
        // --- sifting + public sample for QBER ---
        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < n; i++) if (s.kept[i]) idx.add(i);
        Collections.shuffle(idx, RNG);
        s.sample = Math.max(1, s.sifted / 4);
        s.sampled = new boolean[n];
        for (int t = 0; t < s.sample; t++) {
            int i = idx.get(t); s.sampled[i] = true;
            if (s.aBit[i] != s.bBit[i]) s.sampleErr++;
        }
        s.qber = (double) s.sampleErr / s.sample;
        List<Integer> rawIdx = new ArrayList<>(idx.subList(s.sample, idx.size()));
        Collections.sort(rawIdx);
        s.raw = rawIdx.size();
        int[] ra = new int[s.raw], rb = new int[s.raw], re = new int[s.raw];
        int match = 0;
        for (int k = 0; k < s.raw; k++) {
            int i = rawIdx.get(k);
            ra[k] = s.aBit[i]; rb[k] = s.bBit[i];
            re[k] = s.eBasis[i] >= 0 ? s.eBit[i] : RNG.nextInt(2);   // Eve's best guess of the key bit
            if (re[k] == ra[k]) match++;
        }
        s.eveKnows = s.raw == 0 ? 0 : (double) match / s.raw;
        s.eveKey = sha256b(concat(pack(re), "Q-SENTINEL-PA".getBytes(StandardCharsets.UTF_8)));
        // --- eavesdropper decision ---
        if (s.qber > QBER_LIMIT) {
            s.decision = "ABORTED";
            s.reason = String.format("QBER %.1f%% is above the %.0f%% limit: eavesdropper (or a very noisy line) detected. Key discarded.", s.qber * 100, QBER_LIMIT * 100);
            return s;
        }
        s.secureLen = (int) Math.floor(s.raw * (1 - (1 + EC_EFF) * h2(s.qber)));
        if (s.secureLen < KEY_BITS) {
            s.decision = "ABORTED";
            s.reason = "Only " + Math.max(0, s.secureLen) + " secure bits remain after error correction and privacy amplification (need " + KEY_BITS + "). Use more qubits or a quieter line.";
            return s;
        }
        // --- error correction + confirmation ---
        cascade(ra, rb, s.qber);
        if (!Arrays.equals(ra, rb)) {
            s.decision = "ABORTED";
            s.reason = "Key confirmation failed: residual errors after error correction. Run again.";
            return s;
        }
        // --- privacy amplification: compress to 256 bits ---
        s.key = sha256b(concat(pack(ra), "Q-SENTINEL-PA".getBytes(StandardCharsets.UTF_8)));
        s.fp = sha256("FP" + hex(s.key)).substring(0, 12);
        s.accepted = true; s.decision = "ACCEPTED";
        s.reason = "QBER within limit, channel authenticated, keys confirmed identical. 256-bit AES key derived.";
        return s;
    }

    static byte[] concat(byte[] a, byte[] b) { byte[] c = new byte[a.length + b.length]; System.arraycopy(a, 0, c, 0, a.length); System.arraycopy(b, 0, c, a.length, b.length); return c; }

    /** Cascade-style reconciliation: block parities are compared publicly, binary search fixes the bad bit in Bob's key. */
    static void cascade(int[] a, int[] b, double q) {
        int n = a.length;
        if (n == 0) return;
        int k0 = (int) Math.max(4, Math.round(0.73 / Math.max(q, 0.005)));
        for (int pass = 0; pass < 14; pass++) {
            int k = pass < 3 ? k0 : pass < 7 ? Math.max(4, k0 / 2) : Math.max(3, k0 / 4);
            int[] p = new int[n];
            for (int i = 0; i < n; i++) p[i] = i;
            for (int i = n - 1; i > 0; i--) { int j = RNG.nextInt(i + 1); int t = p[i]; p[i] = p[j]; p[j] = t; }
            for (int s = 0; s < n; s += k) {
                int e = Math.min(n, s + k);
                if (par(a, p, s, e) != par(b, p, s, e)) {
                    int lo = s, hi = e;
                    while (hi - lo > 1) { int mid = (lo + hi) / 2; if (par(a, p, lo, mid) != par(b, p, lo, mid)) hi = mid; else lo = mid; }
                    b[p[lo]] ^= 1;
                }
            }
        }
    }
    static int par(int[] x, int[] p, int s, int e) { int r = 0; for (int i = s; i < e; i++) r ^= x[p[i]]; return r; }

    static double siftedErrorRate(Session s) {
        int err = 0;
        for (int i = 0; i < s.n; i++) if (s.kept[i] && s.aBit[i] != s.bBit[i]) err++;
        return s.sifted == 0 ? 0 : (double) err / s.sifted;
    }

    /** Experiment: measured QBER vs fraction of qubits intercepted by Eve (theory: 25% x fraction). */
    static double[][] experiment(int n, int trials, double noise) {
        double[][] r = new double[11][3];
        for (int k = 0; k <= 10; k++) {
            double f = k / 10.0, sum = 0;
            for (int t = 0; t < trials; t++) { Session s = new Session(); s.n = n; s.eveFrac = f; s.noise = noise; simulate(s); sum += siftedErrorRate(s); }
            r[k][0] = f * 100; r[k][1] = sum / trials * 100; r[k][2] = (0.25 * f + noise * (1 - 0.5 * f)) * 100;
        }
        return r;
    }

    // ===================== SESSION LOG (SHA-256 hash chain) =====================
    static final String GEN = "0".repeat(64);
    static class LogRec {
        int idx; String[] f; String prev, hash;
        String compute() { return sha256(idx + "|" + String.join("|", f) + "|" + prev); }
    }

    // ===================== THEME =====================
    static final Color[] DARK = {new Color(15, 23, 42), new Color(30, 41, 59), new Color(56, 189, 248),
            new Color(34, 197, 94), new Color(239, 68, 68), new Color(226, 232, 240)};
    static final Color[] LIGHT = {new Color(241, 245, 249), new Color(250, 252, 255), new Color(2, 132, 199),
            new Color(22, 163, 74), new Color(220, 38, 38), new Color(15, 23, 42)};
    static Color BG = DARK[0], PANEL = DARK[1], ACC = DARK[2], OK = DARK[3], BAD = DARK[4], TXT = DARK[5];
    static final Color GRAY = new Color(120, 130, 145);
    static boolean dark = true;
    static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 13);

    static Color swap(Color c, Color[] from, Color[] to) {
        for (int i = 0; i < from.length; i++) if (from[i].equals(c)) return to[i];
        return c;
    }
    static void recolor(Component c, Color[] from, Color[] to) {
        Color bg = swap(c.getBackground(), from, to), fg = swap(c.getForeground(), from, to);
        if (!bg.equals(c.getBackground())) c.setBackground(bg);
        if (!fg.equals(c.getForeground())) c.setForeground(fg);
        if (c instanceof javax.swing.text.JTextComponent) ((javax.swing.text.JTextComponent) c).setCaretColor(to[5]);
        if (c instanceof JTable) ((JTable) c).setGridColor(swap(((JTable) c).getGridColor(), from, to));
        if (c instanceof Container) for (Component k : ((Container) c).getComponents()) recolor(k, from, to);
    }

    // ===================== UI HELPERS =====================
    static class TitledPanel extends JPanel {
        final JPanel body = new JPanel(new BorderLayout(8, 8));
        TitledPanel(JLabel title) {
            super(new BorderLayout(8, 8));
            setBackground(PANEL);
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            body.setBackground(PANEL);
            super.add(title, BorderLayout.NORTH);
            super.add(body, BorderLayout.CENTER);
        }
        @Override public void add(Component c, Object constraints) { body.add(c, constraints); }
    }
    static JPanel page(String title) {
        JLabel l = new JLabel(title);
        l.setForeground(ACC); l.setFont(new Font("SansSerif", Font.BOLD, 14));
        return new TitledPanel(l);
    }
    static JPanel row() { JPanel r = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4)); r.setBackground(PANEL); return r; }
    static JLabel lbl(String s) { JLabel l = new JLabel(s); l.setForeground(TXT); return l; }
    static JButton btn(String s, Color c) {
        JButton b = new JButton(s);
        b.setBackground(c); b.setForeground(Color.BLACK); b.setFocusPainted(false); b.setOpaque(true);
        return b;
    }
    static JTextArea area(Color fg) {
        JTextArea a = new JTextArea();
        a.setEditable(false); a.setBackground(BG); a.setForeground(fg); a.setFont(MONO); a.setLineWrap(true); a.setWrapStyleWord(true);
        return a;
    }
    static JTable table(DefaultTableModel m) {
        JTable t = new JTable(m);
        t.setBackground(PANEL); t.setForeground(TXT); t.setGridColor(BG);
        t.setRowHeight(22); t.setFont(MONO); t.setFillsViewportHeight(true);
        t.getTableHeader().setBackground(ACC); t.getTableHeader().setForeground(Color.BLACK);
        return t;
    }
    static DefaultTableModel model(String... cols) {
        return new DefaultTableModel(cols, 0) { public boolean isCellEditable(int r, int c) { return false; } };
    }
    static JTextField field(String s, int w) {
        JTextField f = new JTextField(s, w);
        f.setBackground(BG); f.setForeground(TXT); f.setCaretColor(TXT);
        return f;
    }
    static <T> JComboBox<T> combo(T[] items) {
        JComboBox<T> c = new JComboBox<>(items);
        c.setBackground(BG); c.setForeground(TXT);
        return c;
    }
    static JPanel labeled(String title, JTextArea a) {
        JPanel p = new JPanel(new BorderLayout(4, 4)); p.setBackground(PANEL);
        JLabel l = new JLabel(title); l.setForeground(ACC); l.setFont(new Font("SansSerif", Font.BOLD, 13));
        p.add(l, BorderLayout.NORTH); p.add(new JScrollPane(a), BorderLayout.CENTER);
        return p;
    }
    static String pol(int basis, int bit) { return basis == 0 ? (bit == 0 ? "\u2192" : "\u2191") : (bit == 0 ? "\u2197" : "\u2196"); }

    // ===================== CHART =====================
    static class LineChart extends JPanel {
        double[][] data;
        LineChart() { setBackground(BG); setPreferredSize(new Dimension(300, 300)); }
        protected void paintComponent(Graphics g0) {
            super.paintComponent(g0);
            Graphics2D g = (Graphics2D) g0;
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight(), L = 60, R = 20, T = 30, B = 45;
            if (data == null) {
                g.setColor(TXT); g.setFont(new Font("SansSerif", Font.BOLD, 16));
                g.drawString("Press 'Run experiment' to measure QBER vs eavesdropping", Math.max(10, w / 2 - 230), h / 2);
                return;
            }
            double ymax = 30;
            g.setFont(new Font("SansSerif", Font.PLAIN, 11));
            for (int y = 0; y <= 30; y += 5) {
                int py = T + (int) ((h - T - B) * (1 - y / ymax));
                g.setColor(PANEL); g.drawLine(L, py, w - R, py);
                g.setColor(TXT); g.drawString(y + "%", L - 34, py + 4);
            }
            for (int x = 0; x <= 100; x += 10) {
                int px = L + (int) ((w - L - R) * x / 100.0);
                g.setColor(TXT); g.drawString(x + "%", px - 10, h - B + 16);
            }
            g.drawString("Fraction of qubits intercepted by Eve", w / 2 - 100, h - 8);
            g.drawString("QBER", 10, T - 10);
            int ty = T + (int) ((h - T - B) * (1 - 11 / ymax));
            g.setColor(BAD); g.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{6f, 6f}, 0f));
            g.drawLine(L, ty, w - R, ty); g.drawString("11% abort threshold", w - R - 130, ty - 5);
            g.setColor(ACC);
            for (int i = 0; i < data.length - 1; i++) g.drawLine(px(i, w, L, R), py(data[i][2], h, T, B, ymax), px(i + 1, w, L, R), py(data[i + 1][2], h, T, B, ymax));
            g.setStroke(new BasicStroke(2.5f)); g.setColor(OK);
            for (int i = 0; i < data.length - 1; i++) g.drawLine(px(i, w, L, R), py(data[i][1], h, T, B, ymax), px(i + 1, w, L, R), py(data[i + 1][1], h, T, B, ymax));
            for (int i = 0; i < data.length; i++) g.fillOval(px(i, w, L, R) - 4, py(data[i][1], h, T, B, ymax) - 4, 8, 8);
            g.setStroke(new BasicStroke(1f));
            g.setColor(OK); g.drawString("measured", L + 10, T + 12); g.setColor(ACC); g.drawString("theory (25% x fraction)", L + 80, T + 12);
        }
        int px(int i, int w, int L, int R) { return L + (int) ((w - L - R) * data[i][0] / 100.0); }
        int py(double v, int h, int T, int B, double ymax) { return T + (int) ((h - T - B) * (1 - Math.min(v, ymax) / ymax)); }
    }

    // ===================== MAIN PANEL =====================
    static final List<JPanel> ROOTS = new ArrayList<>();
    static final List<JButton> TOG = new ArrayList<>();
    static void applyTheme(boolean toDark) {
        Color[] from = dark ? DARK : LIGHT, to = toDark ? DARK : LIGHT;
        BG = to[0]; PANEL = to[1]; ACC = to[2]; OK = to[3]; BAD = to[4]; TXT = to[5];
        dark = toDark;
        for (JPanel r : ROOTS) { recolor(r, from, to); r.repaint(); }
        for (JButton b : TOG) b.setText(dark ? "Switch to Light Mode" : "Switch to Dark Mode");
    }

    static final String[] SAMPLE_MSGS = {
            "Convoy Alpha-7 will reach checkpoint Delta at 0530 hrs.",
            "Request air support at grid 4F-218-97, ETA twelve minutes.",
            "Change radio frequency to channel nine at 1800 hrs.",
            "Supply drop confirmed for forward base Kilo, 0400 hrs.",
            "All units hold position until further orders."};

    static class MainPanel extends JPanel {
        // state
        Session last, keySession;
        final List<LogRec> log = new ArrayList<>();
        final Map<Integer, String> tampered = new HashMap<>();
        int msgCounter = 1, sampleIdx = 0;
        List<String> samples = new ArrayList<>(Arrays.asList(SAMPLE_MSGS));
        // tab 1
        JComboBox<Integer> qubits; JSlider eveSl, noiseSl; JCheckBox mitm;
        JLabel eveLbl, noiseLbl, status; JTextArea summary;
        DefaultTableModel qModel = model("#", "Alice bit", "Photon", "Eve (basis->bit)", "Bob basis", "Bob bit", "Bases match", "Result");
        // tab 2
        JTextField msgField; JCheckBox tamperTx; JTextArea aliceA, eveA, bobA;
        // tab 3
        LineChart chart = new LineChart(); DefaultTableModel expModel = model("Eve intercepts", "Measured QBER", "Theory", "Verdict");
        double[][] expData;
        // tab 4
        JTextArea dhArea;
        // tab 5
        DefaultTableModel logModel = model("#", "Time", "Qubits", "Eve %", "Noise %", "Sifted", "QBER %", "Decision", "Key fp", "Block hash");
        JLabel logStatus;

        MainPanel() {
            super(new BorderLayout());
            ROOTS.add(this);
            setBackground(BG);
            Path sf = Paths.get("sample_data", "messages.txt");
            try { if (Files.exists(sf)) { List<String> l = new ArrayList<>(); for (String s : Files.readAllLines(sf)) if (!s.trim().isEmpty()) l.add(s.trim()); if (!l.isEmpty()) samples = l; } }
            catch (IOException ignored) { }
            JPanel bar = row();
            JLabel title = lbl("Q-SENTINEL   Eavesdropper-Aware BB84 Quantum Key Distribution");
            title.setFont(new Font("SansSerif", Font.BOLD, 15)); title.setForeground(ACC);
            JButton theme = btn("Switch to Light Mode", ACC);
            theme.addActionListener(e -> applyTheme(!dark));
            TOG.add(theme);
            bar.add(title); bar.add(theme);
            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("About", aboutTab());
            tabs.addTab("1. BB84 Key Exchange", exchangeTab());
            tabs.addTab("2. Secure Messaging", messagingTab());
            tabs.addTab("3. Eavesdropper Analysis", analysisTab());
            tabs.addTab("4. Classical vs Quantum", classicalTab());
            tabs.addTab("5. Session Log", logTab());
            add(bar, BorderLayout.NORTH); add(tabs, BorderLayout.CENTER);
        }

        // ---------- About ----------
        JPanel aboutTab() {
            JPanel p = page("Why this matters: defence and strategic networks need keys that cannot be silently copied.");
            JTextArea a = area(TXT);
            a.setText("REAL-WORLD USE\n"
                    + "DRDO has completed military field trials of an indigenous fibre-based Quantum Key Distribution (QKD) system, to protect strategic\n"
                    + "communication against future cyber threats. QKD does not rely on hard maths: it relies on a physical law. Measuring a quantum\n"
                    + "state disturbs it, so an eavesdropper leaves a statistical footprint (errors) that the two ends can detect.\n\n"
                    + "THE PROBLEM WITH TODAY'S KEY EXCHANGE\n"
                    + "RSA and Diffie-Hellman rely on factoring / discrete logs. Shor's algorithm on a large quantum computer breaks both. Worse, an\n"
                    + "attacker can record encrypted traffic today and decrypt it later ('harvest now, decrypt later').\n\n"
                    + "WHAT Q-SENTINEL SIMULATES (the full QKD pipeline)\n"
                    + "  1. BB84: Alice sends photons in random bases; Bob measures in random bases; Eve may intercept-resend.\n"
                    + "  2. Classical channel is authenticated with HMAC-SHA256, so a man-in-the-middle cannot fake the announcements.\n"
                    + "  3. Sifting keeps matching bases; a public sample gives the QBER. QBER above 11% => eavesdropper => key discarded.\n"
                    + "  4. Error correction (Cascade-style parity search) and key confirmation make both keys identical.\n"
                    + "  5. Privacy amplification (SHA-256) squeezes out whatever Eve may have learned -> 256-bit key.\n"
                    + "  6. The key drives AES-256-GCM for confidential, tamper-evident messages.\n"
                    + "  7. Every session is recorded in a SHA-256 hash-chained log.\n\n"
                    + "HOW TO DEMO (about 3 minutes)\n"
                    + "  Tab 1: press 'Demo 1: Secure line' (key accepted), then 'Demo 2: Eavesdropper' (QBER about 25%, ABORTED), then 'Demo 3: MITM'.\n"
                    + "  Tab 2: send a message with the accepted key; Eve sees only ciphertext and her guessed key fails; tamper in transit => rejected.\n"
                    + "  Tab 3: run the experiment: QBER rises linearly with Eve's activity and crosses the 11% line.\n"
                    + "  Tab 4: break a small Diffie-Hellman exchange to show the classical weakness QKD avoids.\n"
                    + "  Tab 5: verify the hash-chained log, then tamper with one record.\n\n"
                    + "NOTE: this is a software simulation of the quantum channel (no real photons), as used in academic QKD studies.");
            a.setCaretPosition(0);
            p.add(new JScrollPane(a), BorderLayout.CENTER);
            return p;
        }

        // ---------- Tab 1 ----------
        JPanel exchangeTab() {
            JPanel p = page("Alice sends photons, Bob measures, Eve may listen. The error rate (QBER) reveals her.");
            qubits = combo(new Integer[]{1024, 2048, 4096, 8192}); qubits.setSelectedItem(4096);
            eveSl = new JSlider(0, 100, 0); noiseSl = new JSlider(0, 10, 0);
            for (JSlider s : new JSlider[]{eveSl, noiseSl}) { s.setBackground(PANEL); s.setForeground(TXT); s.setPreferredSize(new Dimension(150, 28)); }
            eveLbl = lbl("0%"); noiseLbl = lbl("0%");
            eveSl.addChangeListener(e -> eveLbl.setText(eveSl.getValue() + "%"));
            noiseSl.addChangeListener(e -> noiseLbl.setText(noiseSl.getValue() + "%"));
            mitm = new JCheckBox("Attacker tampers with classical channel (MITM)");
            mitm.setBackground(PANEL); mitm.setForeground(TXT);
            JButton run = btn("RUN BB84 EXCHANGE", OK), d1 = btn("Demo 1: Secure line", ACC), d2 = btn("Demo 2: Eavesdropper", BAD), d3 = btn("Demo 3: MITM", BAD);
            JPanel r1 = row(), r2 = row();
            r1.add(lbl("Qubits:")); r1.add(qubits); r1.add(lbl("  Eve intercepts:")); r1.add(eveSl); r1.add(eveLbl);
            r1.add(lbl("  Line noise:")); r1.add(noiseSl); r1.add(noiseLbl);
            r2.add(mitm); r2.add(run); r2.add(d1); r2.add(d2); r2.add(d3);
            JPanel top = new JPanel(new GridLayout(2, 1)); top.setBackground(PANEL); top.add(r1); top.add(r2);
            run.addActionListener(e -> doRun());
            d1.addActionListener(e -> { eveSl.setValue(0); noiseSl.setValue(1); mitm.setSelected(false); doRun(); });
            d2.addActionListener(e -> { eveSl.setValue(100); noiseSl.setValue(1); mitm.setSelected(false); doRun(); });
            d3.addActionListener(e -> { eveSl.setValue(0); noiseSl.setValue(1); mitm.setSelected(true); doRun(); });
            JTable t = table(qModel);
            int[] wd = {45, 80, 70, 130, 90, 80, 100, 120};
            for (int i = 0; i < wd.length; i++) t.getColumnModel().getColumn(i).setPreferredWidth(wd[i]);
            t.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                public Component getTableCellRendererComponent(JTable tb, Object v, boolean s, boolean f, int r, int c) {
                    super.getTableCellRendererComponent(tb, v, s, f, r, c);
                    String res = String.valueOf(tb.getValueAt(r, 7));
                    setBackground(PANEL);
                    setForeground(res.contains("ERROR") ? BAD : res.startsWith("KEY") ? OK : res.startsWith("tested") ? ACC : GRAY);
                    setHorizontalAlignment(CENTER);
                    return this;
                }
            });
            status = new JLabel("  Press a Demo button to start", SwingConstants.LEFT);
            status.setFont(new Font("SansSerif", Font.BOLD, 18)); status.setForeground(TXT);
            summary = area(TXT); summary.setRows(9);
            JPanel south = new JPanel(new BorderLayout(4, 4)); south.setBackground(PANEL);
            south.add(status, BorderLayout.NORTH); south.add(new JScrollPane(summary), BorderLayout.CENTER);
            p.add(top, BorderLayout.NORTH); p.add(new JScrollPane(t), BorderLayout.CENTER); p.add(south, BorderLayout.SOUTH);
            return p;
        }

        void doRun() {
            int n = (Integer) qubits.getSelectedItem();
            Session s = run(n, eveSl.getValue() / 100.0, noiseSl.getValue() / 100.0, mitm.isSelected());
            last = s;
            if (s.accepted) keySession = s;
            qModel.setRowCount(0);
            for (int i = 0; i < Math.min(n, 48); i++) {
                boolean match = s.aBasis[i] == s.bBasis[i];
                String res;
                if (!match) res = "discarded";
                else if (s.sampled != null && s.sampled[i]) res = s.aBit[i] == s.bBit[i] ? "tested ok" : "tested ERROR";
                else res = s.aBit[i] == s.bBit[i] ? "KEY BIT" : "KEY ERROR";
                qModel.addRow(new Object[]{i + 1, s.aBit[i], pol(s.aBasis[i], s.aBit[i]),
                        s.eBasis[i] < 0 ? "-" : (s.eBasis[i] == 0 ? "+" : "x") + " -> " + s.eBit[i],
                        s.bBasis[i] == 0 ? "+" : "x", s.bBit[i], match ? "yes" : "no", res});
            }
            status.setText(s.accepted ? "  KEY ACCEPTED   256-bit key established (fingerprint " + s.fp + ")" : "  ABORTED   no key is used");
            status.setForeground(s.accepted ? OK : BAD);
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Qubits sent: %d    Intercepted by Eve: %d    Sifted (bases matched): %d\n", s.n, s.intercepted, s.sifted));
            if (s.authOK && s.qber >= 0) {
                sb.append(String.format("Public sample: %d bits    Errors in sample: %d    QBER = %.2f%%  (limit %.0f%%)\n", s.sample, s.sampleErr, s.qber * 100, QBER_LIMIT * 100));
                sb.append(String.format("Raw key bits left: %d    Secure key length estimate: %d bits\n", s.raw, Math.max(0, s.secureLen)));
                sb.append(String.format("Eve correctly knows %.1f%% of the raw key bits (50%% = pure guessing)\n", s.eveKnows * 100));
            } else sb.append("HMAC authentication of the classical channel: FAILED\n");
            sb.append("\nDECISION: ").append(s.decision).append("  -  ").append(s.reason);
            summary.setText(sb.toString()); summary.setCaretPosition(0);
            summary.setForeground(s.accepted ? OK : BAD);
            addLog(s);
        }

        void addLog(Session s) {
            LogRec r = new LogRec();
            r.idx = log.size() + 1;
            r.f = new String[]{now(), String.valueOf(s.n), String.valueOf(Math.round(s.eveFrac * 100)), String.valueOf(Math.round(s.noise * 100)),
                    String.valueOf(s.sifted), s.qber < 0 ? "n/a" : String.format("%.2f", s.qber * 100), s.decision, s.fp};
            r.prev = log.isEmpty() ? GEN : log.get(log.size() - 1).hash;
            r.hash = r.compute();
            log.add(r);
            refreshLog();
        }

        // ---------- Tab 2 ----------
        JPanel messagingTab() {
            JPanel p = page("The BB84 key encrypts messages with AES-256-GCM. Eve sees only ciphertext.");
            msgField = field(samples.get(0), 48);
            tamperTx = new JCheckBox("Attacker modifies ciphertext in transit"); tamperTx.setBackground(PANEL); tamperTx.setForeground(TXT);
            JButton next = btn("Next sample message", ACC), send = btn("ENCRYPT & SEND", OK);
            JPanel r = row(); r.add(lbl("Message:")); r.add(msgField); r.add(next); r.add(tamperTx); r.add(send);
            aliceA = area(OK); eveA = area(BAD); bobA = area(ACC);
            JPanel g = new JPanel(new GridLayout(1, 3, 8, 0)); g.setBackground(PANEL);
            g.add(labeled("ALICE (sender)", aliceA)); g.add(labeled("EVE (eavesdropper)", eveA)); g.add(labeled("BOB (receiver)", bobA));
            next.addActionListener(e -> { sampleIdx = (sampleIdx + 1) % samples.size(); msgField.setText(samples.get(sampleIdx)); });
            send.addActionListener(e -> sendMessage());
            p.add(r, BorderLayout.NORTH); p.add(g, BorderLayout.CENTER);
            return p;
        }

        void sendMessage() {
            if (keySession == null) { JOptionPane.showMessageDialog(this, "No key yet. Run a successful BB84 exchange in tab 1 first (Demo 1)."); return; }
            String pt = msgField.getText();
            if (pt.isEmpty()) return;
            byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
            byte[] aad = ("session-" + keySession.fp + "-msg-" + msgCounter).getBytes(StandardCharsets.UTF_8);
            try {
                byte[] ct = aes(Cipher.ENCRYPT_MODE, keySession.key, nonce, aad, pt.getBytes(StandardCharsets.UTF_8));
                byte[] tx = ct.clone();
                if (tamperTx.isSelected()) tx[0] ^= 1;
                aliceA.append("Message #" + msgCounter + "\nplaintext:\n" + pt + "\n\nAES-256-GCM key fp: " + keySession.fp + "\nnonce: " + hex(nonce) + "\nciphertext+tag:\n" + hex(ct) + "\n\n");
                String ev;
                try { aes(Cipher.DECRYPT_MODE, keySession.eveKey, nonce, aad, tx); ev = "decrypted (!)"; }
                catch (GeneralSecurityException ex) { ev = "FAILED (authentication tag mismatch)"; }
                eveA.append("Message #" + msgCounter + "\nEve sees only:\n" + hex(tx) + "\n\nEve knows " + String.format("%.0f", keySession.eveKnows * 100) + "% of raw key bits.\nDecrypt with her guessed key: " + ev + "\n\n");
                String bob;
                try { bob = "DECRYPTED OK:\n" + new String(aes(Cipher.DECRYPT_MODE, keySession.key, nonce, aad, tx), StandardCharsets.UTF_8); }
                catch (GeneralSecurityException ex) { bob = "REJECTED: integrity check failed.\nMessage was modified in transit."; }
                bobA.append("Message #" + msgCounter + "\n" + bob + "\n\n");
                msgCounter++;
            } catch (GeneralSecurityException ex) { JOptionPane.showMessageDialog(this, "Crypto error: " + ex.getMessage()); }
        }

        // ---------- Tab 3 ----------
        JPanel analysisTab() {
            JPanel p = page("Every qubit Eve touches adds errors: QBER grows to 25% when she intercepts everything.");
            JButton run = btn("Run experiment (11 points x 8 trials)", OK), export = btn("Export CSV", ACC);
            JPanel top = row(); top.add(run); top.add(export);
            run.addActionListener(e -> {
                run.setEnabled(false);
                new Thread(() -> {
                    double[][] d = experiment(4000, 8, 0);
                    SwingUtilities.invokeLater(() -> {
                        expData = d; chart.data = d; chart.repaint(); expModel.setRowCount(0);
                        for (double[] x : d) expModel.addRow(new Object[]{String.format("%.0f%%", x[0]), String.format("%.2f%%", x[1]), String.format("%.2f%%", x[2]), x[1] > QBER_LIMIT * 100 ? "ABORT (detected)" : "key kept"});
                        run.setEnabled(true);
                    });
                }).start();
            });
            export.addActionListener(e -> {
                if (expData == null) { JOptionPane.showMessageDialog(this, "Run the experiment first."); return; }
                JFileChooser fc = new JFileChooser(new File(".")); fc.setSelectedFile(new File("qber_experiment.csv"));
                if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
                try { writeExperiment(fc.getSelectedFile(), expData); JOptionPane.showMessageDialog(this, "Saved " + fc.getSelectedFile().getName()); }
                catch (IOException ex) { JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage()); }
            });
            JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, chart, new JScrollPane(table(expModel)));
            sp.setResizeWeight(0.7);
            p.add(top, BorderLayout.NORTH); p.add(sp, BorderLayout.CENTER);
            return p;
        }

        // ---------- Tab 4 ----------
        JPanel classicalTab() {
            JPanel p = page("Why QKD: a classical Diffie-Hellman key exchange rests on the discrete-log problem, which Shor's algorithm breaks.");
            JComboBox<Integer> bits = combo(new Integer[]{16, 20, 24, 28, 32});
            JButton go = btn("Eve attacks Diffie-Hellman", BAD);
            JPanel top = row(); top.add(lbl("Prime size (bits):")); top.add(bits); top.add(go);
            dhArea = area(TXT);
            dhArea.setText("Pick a small prime size and press the button. Eve sees p, g, A = g^a mod p and B = g^b mod p, then brute-forces the\n"
                    + "discrete logarithm to recover the shared key.\n\n"
                    + "COMPARISON\n"
                    + "  Diffie-Hellman / RSA : security = mathematical hardness. A large quantum computer (Shor) breaks it. Recorded traffic can\n"
                    + "                         be decrypted later.\n"
                    + "  BB84 QKD             : security = physics. Eve cannot copy or measure a photon without causing errors, so she is DETECTED\n"
                    + "                         and the key is thrown away. Nothing useful is left to decrypt later.\n");
            go.addActionListener(e -> breakDh((Integer) bits.getSelectedItem()));
            p.add(top, BorderLayout.NORTH); p.add(new JScrollPane(dhArea), BorderLayout.CENTER);
            return p;
        }

        void breakDh(int bits) {
            dhArea.setText("Eve is brute-forcing a " + bits + "-bit Diffie-Hellman exchange (8 second limit)...\n");
            new Thread(() -> {
                long P = BigInteger.probablePrime(bits, RNG).longValue(), g = 2;
                long a = 2 + Math.floorMod(RNG.nextLong(), P - 3), b = 2 + Math.floorMod(RNG.nextLong(), P - 3);
                BigInteger bp = BigInteger.valueOf(P), bg = BigInteger.valueOf(g);
                long A = bg.modPow(BigInteger.valueOf(a), bp).longValue(), B = bg.modPow(BigInteger.valueOf(b), bp).longValue();
                long shared = BigInteger.valueOf(B).modPow(BigInteger.valueOf(a), bp).longValue();
                long t0 = System.nanoTime(), cur = 1, x = 0; boolean found = false;
                while (true) {
                    x++; cur = cur * g % P;
                    if (cur == A) { found = true; break; }
                    if ((x & 0xFFFFF) == 0 && System.nanoTime() - t0 > 8_000_000_000L) break;
                }
                double sec = (System.nanoTime() - t0) / 1e9;
                String out;
                if (found) {
                    long eveShared = BigInteger.valueOf(B).modPow(BigInteger.valueOf(x), bp).longValue();
                    out = "p = " + P + ", g = 2\nA = " + A + ", B = " + B + "   (public)\n\nEve found exponent x = " + x + " in " + String.format("%.3f", sec) + " s\n"
                            + "Eve's key = " + eveShared + "\nReal shared key = " + shared + "\n=> " + (eveShared == shared ? "KEY STOLEN. Classical key exchange BROKEN." : "mismatch") 
                            + "\n\nFor 2048-bit primes this is infeasible classically, but Shor's algorithm on a large quantum computer solves it in polynomial time.\nBB84 does not have this weakness: tapping the line is detected (tab 1, Demo 2).";
                } else {
                    double rate = x / sec;
                    out = "Not solved in 8 s (" + String.format("%.0f", rate) + " guesses per second).\nEstimated total time for this size: about " + String.format("%.0f", P / rate) + " s.\nEach extra bit doubles the work, yet Shor's algorithm would still solve any size in polynomial time on a large quantum computer.";
                }
                final String o = out;
                SwingUtilities.invokeLater(() -> dhArea.append("\n" + o));
            }).start();
        }

        // ---------- Tab 5 ----------
        JPanel logTab() {
            JPanel p = page("Every key-exchange attempt is sealed in a SHA-256 hash chain: editing a record breaks everything after it.");
            JButton verify = btn("Verify chain", ACC), tamper = btn("Tamper with selected record (toggle)", BAD), export = btn("Export CSV", ACC);
            logStatus = lbl("  Chain: EMPTY");
            JPanel top = row(); top.add(verify); top.add(tamper); top.add(export); top.add(logStatus);
            JTable t = table(logModel);
            t.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                public Component getTableCellRendererComponent(JTable tb, Object v, boolean s, boolean f, int r, int c) {
                    super.getTableCellRendererComponent(tb, v, s, f, r, c);
                    int bad = firstBad();
                    setBackground(PANEL); setForeground(bad >= 0 && r >= bad ? BAD : OK);
                    return this;
                }
            });
            verify.addActionListener(e -> refreshLog());
            tamper.addActionListener(e -> {
                if (log.isEmpty()) return;
                int r = t.getSelectedRow(); if (r < 0) r = 0;
                String[] f = log.get(r).f;
                if (tampered.containsKey(r)) f[6] = tampered.remove(r);
                else { tampered.put(r, f[6]); f[6] = "ACCEPTED"; if (tampered.get(r).equals("ACCEPTED")) f[6] = "ABORTED"; }
                refreshLog();
            });
            export.addActionListener(e -> {
                if (log.isEmpty()) { JOptionPane.showMessageDialog(this, "No sessions yet."); return; }
                JFileChooser fc = new JFileChooser(new File(".")); fc.setSelectedFile(new File("session_log.csv"));
                if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
                try { writeLog(fc.getSelectedFile(), log); JOptionPane.showMessageDialog(this, "Saved " + fc.getSelectedFile().getName()); }
                catch (IOException ex) { JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage()); }
            });
            p.add(top, BorderLayout.NORTH); p.add(new JScrollPane(t), BorderLayout.CENTER);
            return p;
        }

        int firstBad() {
            String prev = GEN;
            for (int i = 0; i < log.size(); i++) {
                LogRec r = log.get(i);
                if (!r.prev.equals(prev) || !r.compute().equals(r.hash)) return i;
                prev = r.hash;
            }
            return -1;
        }
        void refreshLog() {
            logModel.setRowCount(0);
            for (LogRec r : log) {
                Object[] row = new Object[10]; row[0] = r.idx;
                for (int i = 0; i < r.f.length; i++) row[i + 1] = r.f[i];
                row[9] = r.hash.substring(0, 16) + "...";
                logModel.addRow(row);
            }
            int bad = firstBad();
            logStatus.setText(log.isEmpty() ? "  Chain: EMPTY" : bad < 0 ? "  Chain: VALID (" + log.size() + " records)" : "  Chain: BROKEN at record " + (bad + 1));
            logStatus.setForeground(bad < 0 ? OK : BAD);
        }
    }

    // ===================== EXPORTS =====================
    static void writeExperiment(File f, double[][] d) throws IOException {
        try (PrintWriter w = new PrintWriter(f, "UTF-8")) {
            w.println("eve_interception_percent,measured_qber_percent,theoretical_qber_percent");
            for (double[] x : d) w.println(String.format("%.0f,%.2f,%.2f", x[0], x[1], x[2]));
        }
    }
    static void writeLog(File f, List<LogRec> log) throws IOException {
        try (PrintWriter w = new PrintWriter(f, "UTF-8")) {
            w.println("record,time,qubits,eve_percent,noise_percent,sifted,qber_percent,decision,key_fingerprint,block_hash");
            for (LogRec r : log) w.println(r.idx + "," + String.join(",", r.f) + "," + r.hash);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame f = new JFrame("Q-Sentinel: Eavesdropper-Aware BB84 Quantum Key Distribution for Secure Defence Communication");
            f.setContentPane(new MainPanel());
            f.setSize(1180, 800);
            f.setLocationByPlatform(true);
            f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            f.setVisible(true);
        });
    }
}

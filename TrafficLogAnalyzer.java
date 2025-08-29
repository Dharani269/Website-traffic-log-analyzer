import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TrafficLogAnalyzer {

    // ===== Models =====
    static class LogEntry {
        final String ip;
        final String ident; // usually "-"
        final String user;  // authuser
        final ZonedDateTime time;
        final String method;
        final String path;
        final String protocol;
        final int status;
        final long bytes; // - -> 0
        final String referer;
        final String userAgent;
        final String raw;

        LogEntry(String ip, String ident, String user, ZonedDateTime time, String method, String path,
                 String protocol, int status, long bytes, String referer, String userAgent, String raw) {
            this.ip = ip;
            this.ident = ident;
            this.user = user;
            this.time = time;
            this.method = method;
            this.path = path;
            this.protocol = protocol;
            this.status = status;
            this.bytes = bytes;
            this.referer = referer;
            this.userAgent = userAgent;
            this.raw = raw;
        }
    }

    static class DateRange {
        final ZonedDateTime start; // inclusive
        final ZonedDateTime end;   // inclusive

        DateRange(ZonedDateTime start, ZonedDateTime end) {
            this.start = start;
            this.end = end;
        }

        boolean contains(ZonedDateTime t) {
            if (t == null) return false;
            boolean afterStart = (start == null) || !t.isBefore(start);
            boolean beforeEnd  = (end   == null) || !t.isAfter(end);
            return afterStart && beforeEnd;
        }
    }

    // ===== Parser =====
    static class LogParser {
        // Regex for Combined Log Format (lenient on method/path/protocol)
        // Groups:
        // 1 ip 2 ident 3 user 4 datetime 5 method 6 path 7 protocol 8 status 9 bytes 10 referer 11 user-agent
        private static final Pattern COMBINED = Pattern.compile(
                "^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)] \\\"(\\S+)\\s([^\\\"]*)\\s([^\\\"]*)\\\" (\\d{3}) (\\S+) \\\"([^\\\"]*)\\\" \\\"([^\\\"]*)\\\"$"
        );

        private static final DateTimeFormatter DTF =
                DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

        static Optional<LogEntry> parse(String line) {
            line = line == null ? "" : line.trim();
            if (line.isEmpty()) return Optional.empty();
            Matcher m = COMBINED.matcher(line);
            if (!m.find()) {
                return Optional.empty(); // skip unparseable lines
            }
            try {
                String ip = m.group(1);
                String ident = m.group(2);
                String user = m.group(3);
                String datetime = m.group(4);
                String method = m.group(5);
                String path = m.group(6);
                String protocol = m.group(7);
                int status = Integer.parseInt(m.group(8));
                String bytesStr = m.group(9);
                long bytes = bytesStr.equals("-") ? 0L : Long.parseLong(bytesStr);
                String referer = m.group(10);
                String ua = m.group(11);

                ZonedDateTime zdt = ZonedDateTime.parse(datetime, DTF);
                return Optional.of(new LogEntry(ip, ident, user, zdt, method, path, protocol, status, bytes, referer, ua, line));
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        static List<LogEntry> parseFile(Path p, List<String> errorsOut) throws IOException {
            List<LogEntry> entries = new ArrayList<>();
            int lineno = 0;
            try (BufferedReader br = Files.newBufferedReader(p)) {
                String s;
                while ((s = br.readLine()) != null) {
                    lineno++;
                    Optional<LogEntry> le = parse(s);
                    if (le.isPresent()) entries.add(le.get());
                    else if (errorsOut != null) errorsOut.add("Unparsed line " + lineno + ": " + s);
                }
            }
            return entries;
        }
    }

    // ===== Analysis =====
    static class Analyzer {
        final List<LogEntry> all;

        Analyzer(List<LogEntry> all) {
            this.all = all;
        }

        List<LogEntry> filter(DateRange range, String method, Integer statusPrefix, String containsPath, boolean excludeBots) {
            return all.stream().filter(e -> {
                if (range != null && !range.contains(e.time)) return false;
                if (method != null && !method.equalsIgnoreCase(e.method)) return false;
                if (statusPrefix != null && e.status / 100 != statusPrefix) return false;
                if (containsPath != null && (e.path == null || !e.path.toLowerCase().contains(containsPath.toLowerCase())))
                    return false;
                if (excludeBots && isBot(e.userAgent)) return false;
                return true;
            }).collect(Collectors.toList());
        }

        static boolean isBot(String ua) {
            if (ua == null) return false;
            String s = ua.toLowerCase();
            return s.contains("bot") || s.contains("crawler") || s.contains("spider") ||
                   s.contains("slurp") || s.contains("bingpreview") || s.contains("facebookexternalhit") ||
                   s.contains("ahrefs") || s.contains("semrush") || s.contains("yandex") ||
                   s.contains("duckduckbot") || s.contains("google") && s.contains("snippet");
        }

        long totalHits(List<LogEntry> list) {
            return list.size();
        }

        long uniqueVisitors(List<LogEntry> list) {
            return list.stream().map(e -> e.ip).distinct().count();
        }

        long totalBytes(List<LogEntry> list) {
            return list.stream().mapToLong(e -> e.bytes).sum();
        }

        Map<String, Long> topPaths(List<LogEntry> list, int k) {
            return list.stream().collect(Collectors.groupingBy(e -> e.path, Collectors.counting()))
                    .entrySet().stream()
                    .sorted((a,b) -> Long.compare(b.getValue(), a.getValue()))
                    .limit(k)
                    .collect(LinkedHashMap::new, (m,e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
        }

        Map<Integer, Long> statusBuckets(List<LogEntry> list) {
            return list.stream().collect(Collectors.groupingBy(e -> e.status, TreeMap::new, Collectors.counting()));
        }

        Map<Integer, Long> statusFamilies(List<LogEntry> list) {
            return list.stream().collect(Collectors.groupingBy(e -> (e.status/100)*100, TreeMap::new, Collectors.counting()));
        }

        Map<String, Long> hitsPerDay(List<LogEntry> list) {
            return list.stream()
                    .collect(Collectors.groupingBy(e -> e.time.withZoneSameInstant(ZoneId.systemDefault()).toLocalDate().toString(),
                            TreeMap::new, Collectors.counting()));
        }

        Map<Integer, Long> hitsPerHour(List<LogEntry> list) {
            Map<Integer, Long> m = list.stream()
                    .collect(Collectors.groupingBy(e -> e.time.withZoneSameInstant(ZoneId.systemDefault()).getHour(),
                            TreeMap::new, Collectors.counting()));
            // ensure 0-23 present
            for (int i=0;i<24;i++) m.putIfAbsent(i,0L);
            return new TreeMap<>(m);
        }

        Map<String, Long> topReferers(List<LogEntry> list, int k) {
            return list.stream()
                    .filter(e -> e.referer != null && !e.referer.equals("-") && !e.referer.isBlank())
                    .collect(Collectors.groupingBy(e -> e.referer, Collectors.counting()))
                    .entrySet().stream()
                    .sorted((a,b) -> Long.compare(b.getValue(), a.getValue()))
                    .limit(k)
                    .collect(LinkedHashMap::new, (m,e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
        }

        Map<String, Long> topUserAgents(List<LogEntry> list, int k) {
            return list.stream()
                    .collect(Collectors.groupingBy(e -> e.userAgent, Collectors.counting()))
                    .entrySet().stream()
                    .sorted((a,b) -> Long.compare(b.getValue(), a.getValue()))
                    .limit(k)
                    .collect(LinkedHashMap::new, (m,e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
        }

        void exportCSV(List<LogEntry> list, Path out) throws IOException {
            try (BufferedWriter bw = Files.newBufferedWriter(out)) {
                bw.write("ip,ident,user,time,method,path,protocol,status,bytes,referer,userAgent\n");
                for (LogEntry e : list) {
                    bw.write(String.join(",",
                            csv(e.ip), csv(e.ident), csv(e.user),
                            csv(e.time.toString()),
                            csv(e.method), csv(e.path), csv(e.protocol),
                            String.valueOf(e.status), String.valueOf(e.bytes),
                            csv(e.referer), csv(e.userAgent)));
                    bw.write("\n");
                }
            }
        }

        private String csv(String s) {
            if (s == null) return "";
            String v = s.replace("\"", "\"\"");
            if (v.contains(",") || v.contains("\"") || v.contains("\n")) return "\"" + v + "\"";
            return v;
        }
    }

    // ===== Console UI =====
    public static void main(String[] args) {
        new TrafficLogAnalyzer().run(args);
    }

    private void run(String[] args) {
        Scanner sc = new Scanner(System.in);
        Path logPath = null;

        if (args != null && args.length > 0) {
            logPath = Paths.get(args[0]);
        } else {
            System.out.print("Enter log file path: ");
            String p = safeRead(sc);
            if (p != null && !p.isBlank()) logPath = Paths.get(p.trim());
        }

        if (logPath == null || !Files.exists(logPath)) {
            System.out.println("Log file not found. Exiting.");
            return;
        }

        List<String> parseErrors = new ArrayList<>();
        List<LogEntry> entries;
        try {
            entries = LogParser.parseFile(logPath, parseErrors);
        } catch (IOException e) {
            System.out.println("Failed to read: " + e.getMessage());
            return;
        }

        System.out.printf("Parsed %,d entries. Skipped %,d lines.%n", entries.size(), parseErrors.size());
        Analyzer analyzer = new Analyzer(entries);

        DateRange currentRange = null;
        boolean excludeBots = false;
        while (true) {
            System.out.println("\n==== WEBSITE TRAFFIC LOG ANALYSER ====");
            System.out.println("1) Summary");
            System.out.println("2) Top URLs");
            System.out.println("3) Status distribution");
            System.out.println("4) Hits per day");
            System.out.println("5) Hits per hour");
            System.out.println("6) Top referrers");
            System.out.println("7) Top user-agents");
            System.out.println("8) Toggle bot filtering (currently " + (excludeBots ? "ON" : "OFF") + ")");
            System.out.println("9) Set/clear date range filter");
            System.out.println("10) Search path contains ...");
            System.out.println("11) Export filtered to CSV");
            System.out.println("12) Show unparsed line count");
            System.out.println("0) Exit");
            System.out.print("Choose: ");
            String choice = safeRead(sc);
            if (choice == null) continue;

            switch (choice.trim()) {
                case "1": { // Summary
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    showSummary(analyzer, list);
                    break;
                }
                case "2": { // Top URLs
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    int k = askInt(sc, "How many top URLs (default 20): ", 20);
                    printTopMap("Top URLs", analyzer.topPaths(list, k));
                    break;
                }
                case "3": { // Status distribution
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    Map<Integer, Long> fam = analyzer.statusFamilies(list);
                    System.out.println("Status families (xx0):");
                    fam.forEach((code, cnt) -> System.out.printf("  %dxx : %,d%n", code/100, cnt));
                    System.out.println("Status codes:");
                    analyzer.statusBuckets(list).forEach((code, cnt) -> System.out.printf("  %d : %,d%n", code, cnt));
                    break;
                }
                case "4": { // Hits per day
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    System.out.println("Hits per day:");
                    analyzer.hitsPerDay(list).forEach((d, cnt) -> System.out.printf("  %s : %,d%n", d, cnt));
                    break;
                }
                case "5": { // Hits per hour
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    System.out.println("Hits per hour (0-23):");
                    analyzer.hitsPerHour(list).forEach((h, cnt) -> System.out.printf("  %02d : %,d%n", h, cnt));
                    break;
                }
                case "6": { // Top referrers
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    int k = askInt(sc, "How many top referrers (default 15): ", 15);
                    printTopMap("Top Referrers", analyzer.topReferers(list, k));
                    break;
                }
                case "7": { // Top user-agents
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    int k = askInt(sc, "How many top user-agents (default 15): ", 15);
                    printTopMap("Top User-Agents", analyzer.topUserAgents(list, k));
                    break;
                }
                case "8": {
                    excludeBots = !excludeBots;
                    System.out.println("Bot filtering is now " + (excludeBots ? "ON" : "OFF"));
                    break;
                }
                case "9": { // Date range
                    System.out.println("Enter start datetime [dd/MMM/yyyy:HH:mm:ss Z] or blank to clear:");
                    String s = safeRead(sc);
                    ZonedDateTime start = null, end = null;
                    if (s != null && !s.isBlank()) {
                        start = parseZdt(s.trim());
                        if (start == null) {
                            System.out.println("Invalid format.");
                            break;
                        }
                        System.out.println("Enter end datetime [dd/MMM/yyyy:HH:mm:ss Z]:");
                        String e = safeRead(sc);
                        end = parseZdt(e);
                        if (end == null) {
                            System.out.println("Invalid format.");
                            break;
                        }
                        currentRange = new DateRange(start, end);
                        System.out.println("Applied range: " + start + " to " + end);
                    } else {
                        currentRange = null;
                        System.out.println("Date range cleared.");
                    }
                    break;
                }
                case "10": { // Search path
                    System.out.print("Substring to match in PATH (case-insensitive): ");
                    String q = safeRead(sc);
                    if (q == null || q.isBlank()) {
                        System.out.println("No query provided.");
                        break;
                    }
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, q.trim(), excludeBots);
                    System.out.printf("Found %,d entries. Show first 20?%n", list.size());
                    list.stream().limit(20).forEach(e ->
                            System.out.printf("%s %-4s %-3d %s%n", e.time, e.method, e.status, e.path));
                    break;
                }
                case "11": { // Export CSV
                    System.out.print("Output CSV file path: ");
                    String p = safeRead(sc);
                    if (p == null || p.isBlank()) {
                        System.out.println("No path provided.");
                        break;
                    }
                    Path out = Paths.get(p.trim());
                    List<LogEntry> list = analyzer.filter(currentRange, null, null, null, excludeBots);
                    try {
                        analyzer.exportCSV(list, out);
                        System.out.println("Exported " + list.size() + " rows to " + out.toAbsolutePath());
                    } catch (IOException ex) {
                        System.out.println("Export failed: " + ex.getMessage());
                    }
                    break;
                }
                case "12": {
                    System.out.printf("Unparsed/skipped lines: %,d%n", parseErrors.size());
                    if (!parseErrors.isEmpty()) {
                        System.out.print("Show first 5 errors? (y/n): ");
                        String yn = safeRead(sc);
                        if (yn != null && yn.toLowerCase().startsWith("y")) {
                            parseErrors.stream().limit(5).forEach(System.out::println);
                        }
                    }
                    break;
                }
                case "0":
                    System.out.println("Bye!");
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void showSummary(Analyzer analyzer, List<LogEntry> list) {
        long hits = analyzer.totalHits(list);
        long uniq = analyzer.uniqueVisitors(list);
        long bytes = analyzer.totalBytes(list);

        System.out.println("--- SUMMARY ---");
        System.out.printf("Total hits         : %,d%n", hits);
        System.out.printf("Unique IPs         : %,d%n", uniq);
        System.out.printf("Bandwidth (bytes)  : %,d%n", bytes);
        System.out.println("Status families    :");
        analyzer.statusFamilies(list).forEach((fam, cnt) ->
                System.out.printf("  %dxx : %,d%n", fam/100, cnt));
        System.out.println("Peak hour (by hits): " + analyzer.hitsPerHour(list).entrySet().stream()
                .max(Comparator.comparingLong(Entry::getValue))
                .map(e -> String.format("%02d:00 with %,d hits", e.getKey(), e.getValue()))
                .orElse("n/a"));
    }

    private static void printTopMap(String title, Map<String, Long> map) {
        System.out.println("--- " + title + " ---");
        int i = 1;
        for (Map.Entry<String, Long> e : map.entrySet()) {
            System.out.printf("%2d) %,7d  %s%n", i++, e.getValue(), e.getKey());
        }
        if (map.isEmpty()) System.out.println("(none)");
    }

    private static String safeRead(Scanner sc) {
        try {
            return sc.nextLine();
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    private static ZonedDateTime parseZdt(String s) {
        if (s == null) return null;
        try {
            DateTimeFormatter DTF = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
            return ZonedDateTime.parse(s.trim(), DTF);
        } catch (Exception e) {
            return null;
        }
    }

    private static int askInt(Scanner sc, String prompt, int def) {
        System.out.print(prompt);
        String s = safeRead(sc);
        if (s == null || s.isBlank()) return def;
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return def; }
    }
}

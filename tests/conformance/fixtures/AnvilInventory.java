import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.util.TestIdResolver;
import java.io.PrintStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.jar.JarFile;

/**
 * List every test template the pinned suite compiles in, from its own class
 * files. Applicability to a particular client is decided at run time from live
 * discovery, so this is the upper bound that reports are compared against.
 */
public class AnvilInventory {
    private static String quote(String text) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }

    private static String names(Annotation[] annotations) {
        List<String> found = new ArrayList<>();
        for (Annotation annotation : annotations) {
            found.add(annotation.annotationType().getSimpleName());
        }
        found.sort(Comparator.naturalOrder());
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < found.size(); i++) {
            out.append(i > 0 ? "," : "").append(quote(found.get(i)));
        }
        return out.append(']').toString();
    }

    /** Annotation values as the suite wrote them, e.g. the supported TLS versions. */
    private static String value(Annotation[] annotations, String simpleName) {
        for (Annotation annotation : annotations) {
            if (annotation.annotationType().getSimpleName().equals(simpleName)) {
                return quote(annotation.toString());
            }
        }
        return "null";
    }

    private static String id(Method method) {
        if (method.isAnnotationPresent(AnvilTest.class)
                || method.isAnnotationPresent(NonCombinatorialAnvilTest.class)) {
            return TestIdResolver.resolveTestId(method);
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        Path jarPath = Path.of(args[0]);
        List<String> rows = new ArrayList<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (!name.startsWith("de/rub/nds/tlstest/suite/tests/") || !name.endsWith(".class")
                        || name.contains("$")) {
                    continue;
                }
                Class<?> type = Class.forName(name.substring(0, name.length() - 6).replace('/', '.'),
                        false, AnvilInventory.class.getClassLoader());
                for (Method method : type.getDeclaredMethods()) {
                    String id = id(method);
                    if (id == null) continue;
                    rows.add("{\"id\":" + quote(id)
                            + ",\"class\":" + quote(type.getName())
                            + ",\"method\":" + quote(method.getName())
                            + ",\"class_annotations\":" + names(type.getAnnotations())
                            + ",\"method_annotations\":" + names(method.getAnnotations())
                            + ",\"class_tls_version\":" + value(type.getAnnotations(), "TlsVersion")
                            + ",\"method_tls_version\":" + value(method.getAnnotations(), "TlsVersion")
                            + ",\"method_condition\":" + value(method.getAnnotations(), "MethodCondition")
                            + "}");
                }
            }
        }
        rows.sort(Comparator.naturalOrder());
        try (PrintStream out = new PrintStream(Files.newOutputStream(Path.of(args[1])), false, "UTF-8")) {
            out.println("[");
            for (int i = 0; i < rows.size(); i++) {
                out.println("  " + rows.get(i) + (i + 1 < rows.size() ? "," : ""));
            }
            out.println("]");
        }
    }
}

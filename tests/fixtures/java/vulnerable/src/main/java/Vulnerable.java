import java.sql.*;
class Vulnerable {
    ResultSet lookup(Statement statement, String name) throws SQLException {
        return statement.executeQuery("SELECT name FROM users WHERE name = '" + name + "'");
    }
}

import java.sql.*;
class Safe {
    ResultSet lookup(Connection connection, String name) throws SQLException {
        PreparedStatement query = connection.prepareStatement("SELECT name FROM users WHERE name = ?");
        query.setString(1, name);
        return query.executeQuery();
    }
}

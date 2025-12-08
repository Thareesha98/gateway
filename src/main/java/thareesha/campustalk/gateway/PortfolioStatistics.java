package thareesha.campustalk.gateway;


import java.time.LocalDate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides read-only analytics metadata for the portfolio sections.
 * This class does not depend on any database or external service.
 * It is safe to add anywhere in your project.
 *
 * Example: It can show how many blogs, certificates, or projects
 * could be displayed on the frontend for demonstration purposes.
 */
public class PortfolioStatistics {

    private final LocalDate generatedDate = LocalDate.now();
    private final Map<String, Integer> sectionCounts;

    /**
     * Creates an analytics snapshot with predefined, static values.
     * These values do not interact with the real database.
     */
    public PortfolioStatistics() {
        Map<String, Integer> temp = new HashMap<>();
        temp.put("blogs", 12);
        temp.put("projects", 7);
        temp.put("certificates", 15);
        temp.put("skills", 24);

        // Make map immutable to prevent accidental modification
        this.sectionCounts = Collections.unmodifiableMap(temp);
    }

    /**
     * Returns the total count for a specific section.
     * Valid keys: blogs, projects, certificates, skills.
     */
    public int getCount(String section) {
        return sectionCounts.getOrDefault(section.toLowerCase(), 0);
    }

    /**
     * Returns an immutable map of all section counts.
     */
    public Map<String, Integer> getAllStatistics() {
        return sectionCounts;
    }

    /**
     * Returns a descriptive message suitable for logs or UI components.
     */
    public String getSummary() {
        return "Portfolio analytics snapshot generated on " + generatedDate 
             + " | Sections tracked: " + sectionCounts.size();
    }

    public LocalDate getGeneratedDate() {
        return generatedDate;
    }

    @Override
    public String toString() {
        return getSummary();
    }
}
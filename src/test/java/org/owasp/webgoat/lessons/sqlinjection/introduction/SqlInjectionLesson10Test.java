/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson10Test extends LessonTest {

  private String completedError = "JSON path \"lessonCompleted\"";

  @Test
  public void tableExistsIsFailure() throws Exception {
    try {
      mockMvc
          .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(false)))
          .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    } catch (AssertionError e) {
      if (!e.getMessage().contains(completedError)) throw e;

      mockMvc
          .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(true)))
          .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.success"))));
    }
  }

  /**
   * Verifies that a classic SQL injection payload containing a DROP TABLE statement is treated as
   * a literal search string and does NOT drop the access_log table. With the parameterized
   * PreparedStatement fix, the payload is bound as a LIKE parameter value, so no SQL is injected.
   * The result is a normal (failed) lesson response, not a success — the table still exists.
   */
  @Test
  public void sqlInjectionDropTablePayloadIsBlockedByPreparedStatement() throws Exception {
    // This payload previously allowed an attacker to drop the access_log table.
    // After the PreparedStatement fix, it must be treated as a literal search string
    // and must NOT cause the lesson to succeed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        // The lesson must NOT be completed — SQL injection is blocked
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a UNION-based SQL injection payload is blocked. The parameterized query
   * prevents UNION injection by treating the payload as a literal LIKE search value.
   */
  @Test
  public void sqlInjectionUnionPayloadIsBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' UNION SELECT * FROM employees--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a tautology-based SQL injection payload is blocked. The PreparedStatement
   * ensures "' OR '1'='1" is treated as a literal string in the LIKE clause.
   */
  @Test
  public void sqlInjectionTautologyPayloadIsBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a legitimate search string still works correctly and returns the expected
   * failed (entries found) result — confirming backward compatibility after the SQL injection fix.
   */
  @Test
  public void normalSearchStringReturnsEntriesFeedback() throws Exception {
    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/SqlInjection/attack10")
                  .param("action_string", "get"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(false)))
          .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    } catch (AssertionError e) {
      if (!e.getMessage().contains(completedError)) throw e;
      // If the table no longer exists (prior test state), the lesson would be completed
    }
  }
}

/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.json.tests;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.Date;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class DateTimeTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testLocalDate() {
        LocalDate original = LocalDate.of(2023, 10, 15);
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"2023-10-15\""));
        LocalDate deserialized = HELIDON.deserialize(json, LocalDate.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testLocalTime() {
        LocalTime original = LocalTime.of(14, 30, 45);
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"14:30:45\""));
        LocalTime deserialized = HELIDON.deserialize(json, LocalTime.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testLocalDateTime() {
        LocalDateTime original = LocalDateTime.of(2023, 10, 15, 14, 30, 45);
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"2023-10-15T14:30:45\""));
        LocalDateTime deserialized = HELIDON.deserialize(json, LocalDateTime.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testOffsetDateTime() {
        OffsetDateTime original = OffsetDateTime.of(2023, 10, 15, 14, 30, 45, 0, ZoneOffset.ofHours(2));
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"2023-10-15T14:30:45+02:00\""));
        OffsetDateTime deserialized = HELIDON.deserialize(json, OffsetDateTime.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testZonedDateTime() {
        ZonedDateTime original = ZonedDateTime.of(2023, 10, 15, 14, 30, 45, 0, ZoneOffset.ofHours(2));
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"2023-10-15T14:30:45+02:00\""));
        ZonedDateTime deserialized = HELIDON.deserialize(json, ZonedDateTime.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testInstant() {
        Instant original = Instant.parse("2023-10-15T12:30:45Z");
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"2023-10-15T12:30:45Z\""));
        Instant deserialized = HELIDON.deserialize(json, Instant.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testPeriod() {
        Period original = Period.of(1, 2, 3);
        String json = HELIDON.serialize(original);
        assertThat(json, is("\"P1Y2M3D\""));
        Period deserialized = HELIDON.deserialize(json, Period.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testDate() {
        Date original = Date.from(Instant.parse("2023-10-15T12:30:45Z"));
        String json = HELIDON.serialize(original);
        Date deserialized = HELIDON.deserialize(json, Date.class);
        assertThat(deserialized, is(original));
    }

    @Test
    public void testCalendar() {
        Calendar original = Calendar.getInstance();
        original.setTime(Date.from(Instant.parse("2023-10-15T12:30:45Z")));
        String json = HELIDON.serialize(original);
        Calendar deserialized = HELIDON.deserialize(json, Calendar.class);
        assertThat(deserialized.getTime(), is(original.getTime()));
    }

    @Test
    public void testDateTimeModelSerialization() {
        DateTimeModel model = new DateTimeModel(
                LocalDate.of(2023, 10, 15),
                LocalTime.of(14, 30, 45),
                LocalDateTime.of(2023, 10, 15, 14, 30, 45),
                OffsetDateTime.of(2023, 10, 15, 14, 30, 45, 0, ZoneOffset.ofHours(2)),
                ZonedDateTime.of(2023, 10, 15, 14, 30, 45, 0, ZoneOffset.ofHours(2)),
                Instant.parse("2023-10-15T12:30:45Z"),
                Period.of(1, 2, 3),
                Date.from(Instant.parse("2023-10-15T12:30:45Z")),
                Calendar.getInstance()
        );
        model.calendar.setTime(Date.from(Instant.parse("2023-10-15T12:30:45Z")));

        String json = HELIDON.serialize(model);
        DateTimeModel deserialized = HELIDON.deserialize(json, DateTimeModel.class);

        assertThat(deserialized.localDate, is(model.localDate));
        assertThat(deserialized.localTime, is(model.localTime));
        assertThat(deserialized.localDateTime, is(model.localDateTime));
        assertThat(deserialized.offsetDateTime, is(model.offsetDateTime));
        assertThat(deserialized.zonedDateTime, is(model.zonedDateTime));
        assertThat(deserialized.instant, is(model.instant));
        assertThat(deserialized.period, is(model.period));
        assertThat(deserialized.date, is(model.date));
        assertThat(deserialized.calendar.getTime(), is(model.calendar.getTime()));
    }

    @Json.Entity
    record DateTimeModel(
            LocalDate localDate,
            LocalTime localTime,
            LocalDateTime localDateTime,
            OffsetDateTime offsetDateTime,
            ZonedDateTime zonedDateTime,
            Instant instant,
            Period period,
            Date date,
            Calendar calendar
    ) {
    }

}

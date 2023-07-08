CREATE SCHEMA IF NOT EXISTS public;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

SET TIME ZONE 'UTC';

DROP TABLE IF EXISTS countries CASCADE;
CREATE TABLE countries (
                           id             SMALLSERIAL PRIMARY KEY,
                           name           VARCHAR(255) NOT NULL,
                           iso3           VARCHAR(3),
                           numeric_code   VARCHAR(3),
                           iso2           VARCHAR(2),
                           phonecode      VARCHAR(255),
                           capital        VARCHAR(255),
                           currency       VARCHAR(255),
                           currency_name  VARCHAR(42),
                           currency_symbol VARCHAR(255),
                           tld            VARCHAR(255),
                           native         VARCHAR(255),
                           region         VARCHAR(12),
                           subregion      VARCHAR(255),
                           timezone_id    INTEGER[],
                           translations   JSONB,
                           latitude       DOUBLE PRECISION,
                           longitude      DOUBLE PRECISION,
                           emoji          VARCHAR(191),
                           emojiU         VARCHAR(191),
                           created_at     TIMESTAMPTZ DEFAULT current_timestamp,
                           updated_at     TIMESTAMPTZ DEFAULT current_timestamp
);

DROP TABLE IF EXISTS timezones CASCADE;
CREATE TABLE timezones (
                           id              SMALLSERIAL PRIMARY KEY,
                           zone_name       VARCHAR(30) NOT NULL,
                           gmt_offset      INTEGER NOT NULL,
                           gmt_offset_name VARCHAR(9) NOT NULL,
                           abbreviation    VARCHAR(5) NOT NULL,
                           tz_name         VARCHAR(53) NOT NULL
);

DROP TABLE IF EXISTS states CASCADE;
CREATE TABLE states (
                        id            SMALLSERIAL PRIMARY KEY NOT NULL,
                        name          VARCHAR(255) NOT NULL,
                        country_id    INTEGER NOT NULL,
                        country_code  CHAR(2) NOT NULL,
                        type          VARCHAR(191),
                        latitude      DECIMAL(10, 8),
                        longitude     DECIMAL(11, 8),
                        created_at    TIMESTAMPTZ DEFAULT NULL,
                        updated_at    TIMESTAMPTZ DEFAULT current_timestamp,
                        FOREIGN KEY (country_id) REFERENCES countries (id)
);
DROP TABLE IF EXISTS cities CASCADE;
CREATE TABLE cities (
                        id            SERIAL PRIMARY KEY,
                        name          VARCHAR(86) NOT NULL,
                        state_id      SMALLINT NOT NULL,
                        state_code    VARCHAR(255) NOT NULL,
                        country_id    SMALLINT NOT NULL,
                        country_code  CHAR(2) NOT NULL,
                        latitude      DECIMAL(10, 8) NOT NULL,
                        longitude     DECIMAL(11, 8) NOT NULL,
                        created_at    TIMESTAMPTZ DEFAULT '2014-01-01 06:31:01',
                        updated_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        wiki_data_id    VARCHAR(255) DEFAULT NULL,
                        CONSTRAINT fk_cities_state FOREIGN KEY (state_id) REFERENCES states (id),
                        CONSTRAINT fk_cities_country FOREIGN KEY (country_id) REFERENCES countries (id)
);

CREATE TABLE IF NOT EXISTS "country_city_state_map"
(
    "id"         UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'country_city_junction')),
    "country_id" SMALLSERIAL NOT NULL,
    "state_id"   SMALLSERIAL NOT NULL,
    "city_id"    SERIAL      NOT NULL
);
ALTER TABLE country_city_state_map
    ADD FOREIGN KEY (country_id) REFERENCES countries (id);
ALTER TABLE country_city_state_map
    ADD FOREIGN KEY (city_id) REFERENCES cities (id);
ALTER TABLE country_city_state_map
    ADD FOREIGN KEY (state_id) REFERENCES states (id);

ALTER TABLE country_city_state_map
    DROP CONSTRAINT IF EXISTS country_to_city;
ALTER TABLE country_city_state_map
    ADD CONSTRAINT country_to_city UNIQUE (country_id, city_id);

CREATE TABLE IF NOT EXISTS "reports"
(
    "id"            UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'review_replies')),
    "report_reason" VARCHAR(60) NOT NULL, -- at least not specified
    "status"        VARCHAR(20) NOT NULL  -- at least one status.
);

CREATE TABLE IF NOT EXISTS "places"
(
    "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'places'))
);
CREATE TABLE IF NOT EXISTS "places_reports"
(
    "place_id"  UUID NOT NULL,
    "report_id" UUID NOT NULL
);
ALTER TABLE places_reports
    ADD FOREIGN KEY (place_id) REFERENCES places (id);
ALTER TABLE places_reports
    ADD FOREIGN KEY (report_id) REFERENCES reports (id);


CREATE TABLE IF NOT EXISTS "users"
(
    "id"                       UUID PRIMARY KEY                  DEFAULT uuid_generate_v4(),
    "email"                    VARCHAR(255) UNIQUE      NOT NULL,
    "email_last_updated_at"    TIMESTAMP WITH TIME ZONE          DEFAULT NOW() NOT NULL,
    "username"                 VARCHAR(24) UNIQUE       NOT NULL,
    "username_last_updated_at" TIMESTAMP WITH TIME ZONE          DEFAULT NOW() NOT NULL,
    "password"                 VARCHAR(64)              NOT NULL,
    "created_at"               TIMESTAMP WITH TIME ZONE          DEFAULT NOW() NOT NULL,
    "updated_at"               TIMESTAMP WITH TIME ZONE          DEFAULT NOW() NOT NULL,
    "phone_number"             VARCHAR(20) UNIQUE       NOT NULL,
    "role"                     VARCHAR(25)              NOT NULL,
    "place_id"                 UUID                              DEFAULT NULL,
    "banned"                   BOOLEAN                  NOT NULL DEFAULT false,
    "reputation"               SMALLINT                 NOT NULL DEFAULT 0,
    "session_token"            VARCHAR(255)             NOT NULL,
    "refresh_token"            VARCHAR(255)             NOT NULL,
    "verified"                 BOOLEAN                  NOT NULL DEFAULT false,
    "location"                 UUID                              DEFAULT NULL,
    "last_login_ip"            inet,
    "last_login_at"            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    "possible_spammer"         BOOLEAN                  NOT NULL DEFAULT false
);
ALTER TABLE "users"
    ADD FOREIGN KEY (location) REFERENCES "country_city_state_map" ("id");
ALTER TABLE "users"
    ADD FOREIGN KEY ("place_id") REFERENCES "places" ("id");

CREATE TABLE IF NOT EXISTS "user_reports"
(
    "user_id"     UUID NOT NULL,
    "reporter_id" UUID NOT NULL,
    "report_id"   UUID NOT NULL
);

ALTER TABLE user_reports
    ADD FOREIGN KEY (user_id) REFERENCES users (id);
ALTER TABLE user_reports
    ADD FOREIGN KEY (report_id) REFERENCES reports (id);
ALTER TABLE user_reports
    ADD FOREIGN KEY (reporter_id) REFERENCES users (id);

ALTER TABLE user_reports
    DROP CONSTRAINT IF EXISTS user_to_reports;
ALTER TABLE user_reports
    ADD CONSTRAINT user_to_reports UNIQUE (user_id, report_id);


CREATE TABLE IF NOT EXISTS "reviews"
(
    "id"            UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'reviews')),
    "user_id"       UUID                     NOT NULL,
    "place_id"      UUID                     NOT NULL,
    "review_text"   VARCHAR(2048)            NOT NULL,
    "review_title"  VARCHAR(72)              NOT NULL,
    "created_at"    TIMESTAMP WITH TIME ZONE NOT NULL,
    "updated_at"    TIMESTAMP WITH TIME ZONE NOT NULL,
    "helpful_count" SMALLINT         DEFAULT 0,
    "dislike_count" SMALLINT         DEFAULT 0
);
ALTER TABLE "reviews"
    ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");
ALTER TABLE "reviews"
    ADD FOREIGN KEY ("place_id") REFERENCES "places" ("id");

CREATE TABLE IF NOT EXISTS "review_reports"
(
    "review_id" UUID,
    "report_id" UUID
);
ALTER TABLE review_reports
    ADD FOREIGN KEY (review_id) REFERENCES reviews (id);
ALTER TABLE review_reports
    ADD FOREIGN KEY (report_id) REFERENCES reports (id);

ALTER TABLE review_reports
    DROP CONSTRAINT IF EXISTS review_to_reports;
ALTER TABLE review_reports
    ADD CONSTRAINT review_to_reports UNIQUE (review_id, report_id);

CREATE TABLE IF NOT EXISTS "review_reply"
(
    "id"            UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'review_replies')),
    "reply_text"    VARCHAR(2048)            NOT NULL,
    "helpful_count" SMALLINT         DEFAULT 0,
    "dislike_count" SMALLINT         DEFAULT 0,
    "created_at"    TIMESTAMP WITH TIME ZONE NOT NULL,
    "updated_at"    TIMESTAMP WITH TIME ZONE NOT NULL,
    "user_id"       UUID                     NOT NULL,
    "review_id"     UUID                     NOT NULL
);
ALTER TABLE "review_reply"
    ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");
ALTER TABLE "review_reply"
    ADD FOREIGN KEY ("review_id") REFERENCES "reviews" ("id");

CREATE TABLE IF NOT EXISTS "review_reply_reports"
(
    "review_reply_id" UUID NOT NULL,
    "report_id"       UUID NOT NULL
);
ALTER TABLE review_reply_reports
    ADD FOREIGN KEY (review_reply_id) REFERENCES review_reply (id);
ALTER TABLE review_reply_reports
    ADD FOREIGN KEY (report_id) REFERENCES reports (id);

ALTER TABLE review_reply_reports
    DROP CONSTRAINT IF EXISTS review_replies_to_reports;
ALTER TABLE review_reply_reports
    ADD CONSTRAINT review_replies_to_reports UNIQUE (review_reply_id, report_id);

-- Add a trigger to reject updates that violate the minimum character limit
CREATE OR REPLACE FUNCTION check_min_char_limit() RETURNS TRIGGER AS
$$
BEGIN
    IF LENGTH(NEW.review_title) < 3 THEN
        RAISE EXCEPTION 'Minimum character limit of 3 not met for review_title';
    END IF;

    IF LENGTH(NEW.review_text) < 72 THEN
        RAISE EXCEPTION 'Minimum character limit of 72 is not met for review_text';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER enforce_min_char_limit
    BEFORE UPDATE OR INSERT
    ON reviews
    FOR EACH ROW
EXECUTE FUNCTION check_min_char_limit();

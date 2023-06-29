CREATE SCHEMA IF NOT EXISTS public;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

SET TIME ZONE 'UTC';

CREATE TABLE IF NOT EXISTS "countries" (
                                           "id" SMALLSERIAL PRIMARY KEY,
                                           "name" varchar(56) NOT NULL
);

CREATE TABLE IF NOT EXISTS "cities" (
                                        "id" SMALLSERIAL PRIMARY KEY,
                                        "name" varchar(85) NOT NULL,
                                        "districts" json
);

CREATE TABLE IF NOT EXISTS "country_city_state_map" (
                                                        "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'country_city_junction')),
                                                        "country_id" SMALLSERIAL NOT NULL,
                                                        "state_id" SMALLSERIAL NOT NULL,
                                                        "city_id" SERIAL NOT NULL
);
ALTER TABLE country_city_state_map ADD FOREIGN KEY (country_id) REFERENCES countries(id);
ALTER TABLE country_city_state_map ADD FOREIGN KEY (city_id) REFERENCES cities(id);
ALTER TABLE country_city_state_map ADD FOREIGN KEY (state_id) REFERENCES states(id);

ALTER TABLE country_city_state_map DROP CONSTRAINT IF EXISTS  country_to_city;
ALTER TABLE country_city_state_map ADD CONSTRAINT country_to_city UNIQUE (country_id, city_id);

CREATE TABLE IF NOT EXISTS "reports" (
                                         "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'review_replies')),
                                         "report_reason" VARCHAR(60) NOT NULL, -- at least not specified
                                         "status" VARCHAR(20) NOT NULL -- at least one status.
);

CREATE TABLE IF NOT EXISTS "places" (
    "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'places'))
);
CREATE TABLE IF NOT EXISTS "places_reports" (
                                                "place_id" UUID NOT NULL,
                                                "report_id" UUID NOT NULL
);
ALTER TABLE places_reports ADD FOREIGN KEY (place_id) REFERENCES places(id);
ALTER TABLE places_reports ADD FOREIGN KEY (report_id) REFERENCES reports(id);


CREATE TABLE IF NOT EXISTS "users" (
                                       "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                       "email" VARCHAR(255) UNIQUE NOT NULL,
                                       "username" VARCHAR(24) UNIQUE NOT NULL,
                                       "password" VARCHAR(64) NOT NULL,
                                       "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                                       "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                                       "phone_number" VARCHAR(20) UNIQUE NOT NULL,
                                       "role" VARCHAR(25) NOT NULL,
                                       "place_id" UUID,
                                       "banned" BOOLEAN NOT NULL,
                                       "reputation" SMALLINT NOT NULL,
                                       "review_count" SMALLINT NOT NULL,
                                       "session_token" VARCHAR(255) NOT NULL,
                                       "refresh_token" VARCHAR(255) NOT NULL,
                                       "verified" BOOLEAN NOT NULL,
                                       "location" UUID,
                                       "last_login_ip" inet,
                                       "possible_spammer" BOOLEAN NOT NULL
);
ALTER TABLE "users" ADD FOREIGN KEY (location) REFERENCES "country_city_state_map" ("id");
ALTER TABLE "users" ADD FOREIGN KEY ("place_id") REFERENCES "places" ("id");

CREATE TABLE IF NOT EXISTS "user_reports" (
                                              "user_id" UUID NOT NULL,
                                              "reporter_id" UUID NOT NULL,
                                              "report_id" UUID NOT NULL
);

ALTER TABLE user_reports ADD FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE user_reports ADD FOREIGN KEY (report_id) REFERENCES reports(id);
ALTER TABLE user_reports ADD FOREIGN KEY (reporter_id) REFERENCES users(id);

ALTER TABLE user_reports DROP CONSTRAINT IF EXISTS user_to_reports;
ALTER TABLE user_reports ADD CONSTRAINT user_to_reports UNIQUE(user_id, report_id);


CREATE TABLE IF NOT EXISTS  "reviews" (
                                          "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'reviews')),
                                          "user_id" UUID NOT NULL,
                                          "place_id" UUID NOT NULL,
                                          "review_text" VARCHAR(2048) NOT NULL,
                                          "review_title" VARCHAR(72) NOT NULL,
                                          "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                                          "updated_at" TIMESTAMP WITH TIME ZONE  NOT NULL,
                                          "helpful_count" SMALLINT DEFAULT 0,
                                          "dislike_count" SMALLINT DEFAULT 0
);
ALTER TABLE "reviews" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");
ALTER TABLE "reviews" ADD FOREIGN KEY ("place_id") REFERENCES "places" ("id");

CREATE TABLE IF NOT EXISTS "review_reports" (
                                                "review_id" UUID,
                                                "report_id" UUID
);
ALTER TABLE review_reports ADD FOREIGN KEY (review_id) REFERENCES reviews(id);
ALTER TABLE review_reports ADD FOREIGN KEY (report_id) REFERENCES reports(id);

ALTER TABLE review_reports DROP CONSTRAINT IF EXISTS review_to_reports;
ALTER TABLE review_reports ADD CONSTRAINT review_to_reports UNIQUE(review_id, report_id);

CREATE TABLE IF NOT EXISTS "review_reply" (
                                              "id" UUID PRIMARY KEY DEFAULT (uuid_generate_v5(uuid_ns_dns(), 'review_replies')),
                                              "reply_text" VARCHAR(2048) NOT NULL,
                                              "helpful_count" SMALLINT DEFAULT 0,
                                              "dislike_count" SMALLINT DEFAULT 0,
                                              "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                                              "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                                              "user_id" UUID NOT NULL,
                                              "review_id" UUID NOT NULL
);
ALTER TABLE "review_reply" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");
ALTER TABLE "review_reply" ADD FOREIGN KEY ("review_id") REFERENCES "reviews" ("id");

CREATE TABLE IF NOT EXISTS "review_reply_reports" (
                                                      "review_reply_id" UUID NOT NULL,
                                                      "report_id" UUID NOT NULL
);
ALTER TABLE review_reply_reports ADD FOREIGN KEY (review_reply_id) REFERENCES review_reply(id);
ALTER TABLE review_reply_reports ADD FOREIGN KEY (report_id) REFERENCES reports(id);

ALTER TABLE review_reply_reports DROP CONSTRAINT IF EXISTS review_replies_to_reports;
ALTER TABLE review_reply_reports ADD CONSTRAINT review_replies_to_reports UNIQUE(review_reply_id, report_id);

-- Add a trigger to reject updates that violate the minimum character limit
CREATE OR REPLACE FUNCTION check_min_char_limit() RETURNS TRIGGER AS $$
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
    BEFORE UPDATE OR INSERT ON reviews
    FOR EACH ROW
EXECUTE FUNCTION check_min_char_limit();

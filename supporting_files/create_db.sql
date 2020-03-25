BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "tlsh_cluster" (
	"root_hash"	TEXT NOT NULL,
	PRIMARY KEY("root_hash")
);
CREATE TABLE IF NOT EXISTS "warning" (
	"file"	TEXT NOT NULL,
	"warning"	TEXT NOT NULL,
	PRIMARY KEY("file","warning")
);
CREATE TABLE IF NOT EXISTS "file_contains_resource" (
	"source_file_hash"	TEXT NOT NULL,
	"resource_hash"	TEXT NOT NULL,
	PRIMARY KEY("source_file_hash","resource_hash"),
	FOREIGN KEY("source_file_hash") REFERENCES "file"("sha256")
);
CREATE TABLE IF NOT EXISTS "file_unpacks_to" (
	"source_file"	TEXT NOT NULL,
	"destination_file"	TEXT NOT NULL,
	FOREIGN KEY("source_file") REFERENCES "file"("sha256"),
	FOREIGN KEY("destination_file") REFERENCES "file"("sha256"),
	PRIMARY KEY("source_file","destination_file")
);
CREATE TABLE IF NOT EXISTS "file" (
	"sha256"	TEXT NOT NULL UNIQUE,
	"md5"	TEXT NOT NULL,
	"path"	TEXT NOT NULL,
	"family"	TEXT,
	"suspicious"	INTEGER NOT NULL DEFAULT 0,
	"imphash"	TEXT,
	"icon_hash"	TEXT,
	"tlsh"	TEXT,
	"tlsh_cluster"	TEXT,
	"obfuscation_type"	TEXT DEFAULT 'none',
	"obfuscation_packer"	TEXT,
	"obfuscation_protector"	TEXT,
	FOREIGN KEY("tlsh_cluster") REFERENCES "tlsh_cluster"("root_hash"),
	PRIMARY KEY("sha256")
);
CREATE INDEX IF NOT EXISTS "imphash_index" ON "file" (
	"imphash"
) WHERE "imphash" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "icon_hash_index" ON "file" (
	"icon_hash"
) WHERE "icon_hash" IS NOT NULL;
COMMIT;

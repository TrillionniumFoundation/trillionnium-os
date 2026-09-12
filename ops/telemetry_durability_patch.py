from pathlib import Path

path = Path("planned/crates/trillionnium-telemetry/src/catalog.rs")
text = path.read_text()
old = 'pub const DURABLE_PROJECTION_SCHEMA: &str = "trillionnium.owner-open.durable-metric-projection.v1";\n'
new = old + 'pub const DURABILITY_JOURNAL_COMMITMENT_SCHEMA: &str =\n    "trillionnium.owner-open.metric-journal-commitment.v1";\n'
assert text.count(old) == 1
text = text.replace(old, new, 1)

old = '''impl DurabilityReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DURABILITY_RECEIPT_SCHEMA
            || !self.file_fsync_confirmed
            || !self.directory_fsync_confirmed
        {
            return invalid("metric durability receipt is incomplete");
        }
        require_lower_hex(&self.source_commit, 40, "durability source commit")?;
        require_lower_hex(&self.source_tree, 40, "durability source tree")?;
        require_lower_hex(
            &self.journal_record_digest,
            64,
            "durability journal record digest",
        )?;
        Ok(())
    }
}
'''
new = '''impl DurabilityReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DURABILITY_RECEIPT_SCHEMA
            || !self.file_fsync_confirmed
            || !self.directory_fsync_confirmed
        {
            return invalid("metric durability receipt is incomplete");
        }
        require_lower_hex(&self.source_commit, 40, "durability source commit")?;
        require_lower_hex(&self.source_tree, 40, "durability source tree")?;
        require_lower_hex(
            &self.journal_record_digest,
            64,
            "durability journal record digest",
        )?;
        Ok(())
    }

    pub fn journal_record_digest_for_projection(
        source_commit: &str,
        source_tree: &str,
        projection: &MetricProjection,
    ) -> Result<String> {
        projection.validate()?;
        require_lower_hex(source_commit, 40, "durability source commit")?;
        require_lower_hex(source_tree, 40, "durability source tree")?;
        #[derive(Serialize)]
        struct JournalCommitment<'a> {
            schema: &'static str,
            source_commit: &'a str,
            source_tree: &'a str,
            projection_digest: &'a str,
        }
        let commitment = JournalCommitment {
            schema: DURABILITY_JOURNAL_COMMITMENT_SCHEMA,
            source_commit,
            source_tree,
            projection_digest: &projection.projection_digest,
        };
        let bytes = serde_json::to_vec(&commitment).map_err(|error| {
            TelemetryError::Invalid(format!("metric journal commitment encode: {error}"))
        })?;
        Ok(hex_digest(&bytes))
    }

    fn validate_projection_binding(&self, projection: &MetricProjection) -> Result<()> {
        let expected = Self::journal_record_digest_for_projection(
            &self.source_commit,
            &self.source_tree,
            projection,
        )?;
        if self.journal_record_digest != expected {
            return invalid("metric durability receipt does not bind the exact projection");
        }
        Ok(())
    }
}
'''
assert text.count(old) == 1
text = text.replace(old, new, 1)

old = '''        projection.validate()?;
        durability.validate()?;
        if !projection.coverage_complete {
'''
new = '''        projection.validate()?;
        durability.validate()?;
        durability.validate_projection_binding(&projection)?;
        if !projection.coverage_complete {
'''
assert text.count(old) == 1
text = text.replace(old, new, 1)

old = '''        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        assert!(!projection.coverage_complete);
        assert!(DurableMetricProjection::seal(projection, durability()).is_err());
'''
new = '''        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        assert!(!projection.coverage_complete);
        let receipt = durability(&projection);
        assert!(DurableMetricProjection::seal(projection, receipt).is_err());
'''
assert text.count(old) == 1
text = text.replace(old, new, 1)

old = '''        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        let sealed = DurableMetricProjection::seal(projection.clone(), durability()).unwrap();
        assert!(sealed.durable_complete);
        let mut incomplete = durability();
        incomplete.directory_fsync_confirmed = false;
        assert!(DurableMetricProjection::seal(projection, incomplete).is_err());
    }

    fn durability() -> DurabilityReceipt {
        DurabilityReceipt {
            schema: DURABILITY_RECEIPT_SCHEMA.to_string(),
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(40),
            journal_record_digest: "c".repeat(64),
            file_fsync_confirmed: true,
            directory_fsync_confirmed: true,
        }
    }
'''
new = '''        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        let sealed =
            DurableMetricProjection::seal(projection.clone(), durability(&projection)).unwrap();
        assert!(sealed.durable_complete);
        let mut incomplete = durability(&projection);
        incomplete.directory_fsync_confirmed = false;
        assert!(DurableMetricProjection::seal(projection, incomplete).is_err());
    }

    #[test]
    fn durability_receipt_rejects_a_different_projection() {
        let first_ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        first_ingestor.ingest(event(0, 10, "accept")).unwrap();
        let first = first_ingestor.project("broker.accept.duration_ms").unwrap();
        let receipt = durability(&first);

        let second_ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        let mut changed = event(0, 10, "accept");
        changed.value = 2.5;
        second_ingestor.ingest(changed).unwrap();
        let second = second_ingestor.project("broker.accept.duration_ms").unwrap();
        assert_ne!(first.projection_digest, second.projection_digest);
        let error = DurableMetricProjection::seal(second, receipt).unwrap_err();
        assert!(error.to_string().contains("does not bind the exact projection"));
    }

    fn durability(projection: &MetricProjection) -> DurabilityReceipt {
        let source_commit = "a".repeat(40);
        let source_tree = "b".repeat(40);
        let journal_record_digest = DurabilityReceipt::journal_record_digest_for_projection(
            &source_commit,
            &source_tree,
            projection,
        )
        .unwrap();
        DurabilityReceipt {
            schema: DURABILITY_RECEIPT_SCHEMA.to_string(),
            source_commit,
            source_tree,
            journal_record_digest,
            file_fsync_confirmed: true,
            directory_fsync_confirmed: true,
        }
    }
'''
assert text.count(old) == 1
text = text.replace(old, new, 1)
path.write_text(text)

doc = Path("docs/modules/MOD-TELEMETRY.md")
text = doc.read_text()
old = 'A projection may carry `durable_complete=true` only when it is coverage-complete and the owning store supplies a source-bound journal digest plus successful file and parent-directory fsync receipt. Source construction of that receipt is not installed-target evidence.\n'
new = 'A projection may carry `durable_complete=true` only when it is coverage-complete and the owning store supplies a source-bound journal digest plus successful file and parent-directory fsync receipt. The v1 journal commitment is canonical JSON over `{schema, source_commit, source_tree, projection_digest}` and `journal_record_digest` is its SHA-256; `seal` recomputes this commitment and rejects a receipt produced for any other projection. The store must persist and fsync the record identified by that exact digest. Source construction of that receipt is not installed-target evidence.\n'
assert text.count(old) == 1
doc.write_text(text.replace(old, new, 1))

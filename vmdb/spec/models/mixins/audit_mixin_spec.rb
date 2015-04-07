require "spec_helper"

describe AuditMixin do
  before :all do
    @base_class = Class.new(ActiveRecord::Base) do
      def self.name; 'BaseTestClass'; end
      self.table_name = :test_classes
      establish_connection :adapter => "sqlite3", :database => ":memory:"

      connection.create_table :test_classes do |t|
        t.string :foo
        t.string :bar
        t.datetime :lock_version
      end

      include AuditMixin

      validates :foo, :format => /^[^i]/

      attr_accessor :separator
      def separator
        @separator ||= '+'
      end

      def foobar
        "#{foo}#{separator}#{bar}"
      end

      def to_s
        "#{foo}.foo"
      end
    end
  end

  before :each do
    @test_class = Class.new(@base_class) do
      def self.to_s; 'TestClass'; end
    end
  end

  subject { @test_class.create!(:foo => 'aaa', :bar => '123') }

  before :each do
    subject.prepare_for_audit
  end

  context "unchanged" do
    it "reports no changes" do
      expect(subject.changes_for_audit).to match_array([])
    end

    it "knows about the columns" do
      expect(subject.all_values_for_audit).to eq(
        "foo" => 'aaa',
        "bar" => '123',
        "id"  => subject.id,
      )
    end
  end

  context "after a change" do
    before :each do
      subject.foo = 'bbb'
    end

    it "reports the change" do
      expect(subject.changes_for_audit).to match_array([
        ['~', 'foo', 'aaa', 'bbb'],
      ])
    end

    it "can reset tracking" do
      subject.prepare_for_audit
      expect(subject.changes_for_audit).to match_array([])

      subject.bar = '456'
      expect(subject.changes_for_audit).to match_array([
        ['~', 'bar', '123', '456'],
      ])
    end
  end

  context "with extras" do
    before :each do
      @test_class.class_eval do
        def values_for_audit
          {:foobar => foobar}
        end
      end
      subject.prepare_for_audit
    end

    context "unchanged" do
      it "knows the columns and the extras" do
        expect(subject.all_values_for_audit).to eq(
          "foo"    => 'aaa',
          "bar"    => '123',
          "id"     => subject.id,
          "foobar" => 'aaa+123',
        )
      end
    end

    context "when only extra is changed" do
      before :each do
        subject.separator = '/'
      end

      it "recognises the change" do
        expect(subject.all_values_for_audit).to eq(
          "foo"    => 'aaa',
          "bar"    => '123',
          "id"     => subject.id,
          "foobar" => 'aaa/123',
        )

        expect(subject.changes_for_audit).to match_array([
          ['~', 'foobar', 'aaa+123', 'aaa/123'],
        ])
      end

      it "doesn't write the base object" do
        previous = subject.lock_version
        subject.audited_save
        expect(subject.lock_version).to eq(previous)
      end

      it "logs an audit event" do
        expect(AuditEvent).to receive(:success)
        subject.audited_save
      end
    end

    context "when column data is changed" do
      before :each do
        subject.foo = 'bbb'
      end

      it "recognises the changes" do
        expect(subject.all_values_for_audit).to eq(
          "foo"    => 'bbb',
          "bar"    => '123',
          "id"     => subject.id,
          "foobar" => 'bbb+123',
        )

        expect(subject.changes_for_audit).to match_array([
          ['~', 'foo', 'aaa', 'bbb'],
          ['~', 'foobar', 'aaa+123', 'bbb+123'],
        ])
      end

      it "writes the base object" do
        previous = subject.lock_version
        subject.audited_save
        expect(subject.lock_version).not_to eq(previous)
      end

      it "logs an audit event" do
        expect(AuditEvent).to receive(:success)
        subject.audited_save
      end
    end
  end

  describe "block forms" do
    it "only notes in-block changes" do
      subject.foo = 'bbb'

      expect(
        subject.changes_for_audit do
          subject.bar = '456'
        end
      ).to match_array([
        ['~', 'bar', '123', '456'],
      ])
    end

    it "doesn't affect non-block tracking" do
      subject.foo = 'bbb'

      subject.changes_for_audit do
        subject.bar = '456'
      end

      expect(subject.changes_for_audit).to match_array([
        ['~', 'foo', 'aaa', 'bbb'],
        ['~', 'bar', '123', '456'],
      ])
    end

    it "nests" do
      subject.foo = 'bbb'
      subject.bar = '456'

      expect(
        subject.changes_for_audit do
          subject.bar = '000'

          expect(
            subject.changes_for_audit do
              subject.bar = '789'
            end
          ).to match_array([
            ['~', 'bar', '000', '789'],
          ])
        end
      ).to match_array([
        ['~', 'bar', '456', '789'],
      ])

      expect(subject.changes_for_audit).to match_array([
        ['~', 'foo', 'aaa', 'bbb'],
        ['~', 'bar', '123', '789'],
      ])
    end
  end

  describe "events" do
    it "builds a well-formed event entry" do
      expect(subject.audit_event(:record_add, nil, 'DETAILS')).to eq(
        :event        => 'testclass_record_add',
        :target_id    => subject.id,
        :target_class => 'BaseTestClass',
        :userid       => nil,
        :message      => '[aaa.foo] Record created (DETAILS)',
      )

      expect(subject.audit_event(:record_update, nil, 'DETAILS')).to eq(
        :event        => 'testclass_record_update',
        :target_id    => subject.id,
        :target_class => 'BaseTestClass',
        :userid       => nil,
        :message      => '[aaa.foo] Record updated (DETAILS)',
      )
    end

    it "assembles a description of the changes" do
      expect(AuditEvent).to receive(:success).with(
        :event        => 'testclass_record_update',
        :target_id    => subject.id,
        :target_class => 'BaseTestClass',
        :userid       => nil,
        :message      => '[bbb.foo] Record updated (foo:[aaa] to [bbb])',
      )

      subject.audited_save do
        subject.foo = 'bbb'
      end
    end
  end

  describe ".audited_save" do
    it "saves to the database" do
      subject.audited_save do
        subject.foo = 'bbb'
      end

      subject.reload
      expect(subject.foo).to eq('bbb')
    end

    it "returns true after saving successfully" do
      expect(
        subject.audited_save do
          subject.foo = 'bbb'
        end
      ).to be_true
    end

    it "returns false when the underlying save fails" do
      expect(
        subject.audited_save do
          subject.foo = 'invalid'
        end
      ).to be_false

      subject.reload
      expect(subject.foo).to eq('aaa')
    end
  end

  describe ".audit_details" do
    delegate :audit_details, :to => :subject

    it "humanizes changes" do
      {
        ['+', 'foo',            'aaa']        => 'foo:[aaa]',
        ['-', 'foo',            'aaa']        => 'foo:[aaa] to []',
        ['~', 'foo',            'aaa', 'bbb'] => 'foo:[aaa] to [bbb]',
        ['~', 'foo',            'aaa', nil]   => 'foo:[aaa] to []',
        ['~', 'foo',            nil,   'bbb'] => 'foo:[bbb]',
        ['+', 'foo.bar',        'aaa']        => 'foo.bar:[aaa]',
        ['+', 'foo.bar[0].baz', 'aaa']        => 'foo.bar[0].baz:[aaa]',
      }.each do |from, to|
        expect(audit_details([from])).to eq([to])
      end
    end

    it "processes an array" do
      expect(audit_details([
        ['+', 'foo', 'aaa'],
        ['-', 'bar', '123'],
      ])).to eq([
        'foo:[aaa]',
        'bar:[123] to []',
      ])
    end

    it "skips hidden attributes" do
      expect(audit_details([
        ['+', 'foo', 'aaa'],
        ['+', 'verify', 'xxx'],
      ])).to eq([
        'foo:[aaa]',
      ])
    end

    it "masks secrets" do
      expect(audit_details([
        ['+', 'foo', 'aaa'],
        ['+', 'password', 'xxx'],
      ])).to eq([
        'foo:[aaa]',
        'password:[*]',
      ])
    end

    it "notes changes to secrets" do
      expect(audit_details([
        ['~', 'foo', 'aaa', 'bbb'],
        ['~', 'password', 'xxx', 'yyy'],
        ['~', 'another_password', 'xxx', nil],
      ])).to eq([
        'foo:[aaa] to [bbb]',
        'password:[*] to [*]',
        'another_password:[*] to []',
      ])
    end
  end
end

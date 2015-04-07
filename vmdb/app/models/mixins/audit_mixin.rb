module AuditMixin
  def audited_save(event = nil, current_user = User.current_user)
    result = nil

    transaction(:requires_new => true) do
      changes = changes_for_audit do
        yield if block_given?
        result = save
      end

      if result
        audit_successful_save event, current_user, changes
      else
        raise ActiveRecord::Rollback
      end
    end

    result
  end

  def audit_successful_save(event = nil, current_user = User.current_user, changes = nil)
    event ||= new_record? ? :record_add : :record_update

    changes ||= changes_for_audit
    detail = audit_details(changes).join(', ')

    AuditEvent.success(audit_event(event, current_user, detail))
  end

  def all_values_for_audit
    attributes.merge(values_for_audit).stringify_keys
  end

  def prepare_for_audit
    @audit_before = all_values_for_audit
  end

  def changes_for_audit
    if block_given?
      audit_before = all_values_for_audit
      yield
    else
      audit_before = @audit_before
    end

    audit_after = all_values_for_audit

    HashDiff.diff(audit_before, audit_after)
  end

  def audit_event(event, current_user, detail)
    message = case event
              when :record_add; "Record created"
              when :record_update; "Record updated"
              end

    message = "[#{self}] #{message} (#{detail})"

    {
      :event        => "#{self.class.to_s.downcase}_#{event}",
      :target_id    => id,
      :target_class => self.class.base_class.name,
      :userid       => current_user.id,
      :message      => message,
    }
  end

  def audit_details(changes)
    changes.map do |op, k, before, after|
      next if skip_attribute_for_audit?(k)

      before, after = nil, before if op == '+'

      if mask_attribute_for_audit?(k)
        masked_before = before.presence && '*'
        masked_after = after.presence && '*'
      else
        masked_before = before
        masked_after = after
      end

      if before.nil?
        "#{k}:[#{masked_after}]"
      else
        "#{k}:[#{masked_before}] to [#{masked_after}]"
      end
    end.compact
  end

  protected

  # Override this in your model, to publish additional/non-column
  # attributes in audit entries.
  #
  #   def values_for_audit
  #     {
  #       :remote_userid => authentication_userid(:remote),
  #       :remote_password => authentication_password(:remote),
  #     }
  #   end
  #
  def values_for_audit
    {}
  end

  def mask_attribute_for_audit?(attribute)
    attribute.ends_with?("password") ||
      attribute.ends_with?("_pwd") ||
      attribute.ends_with?("amazon_secret")
  end

  def skip_attribute_for_audit?(attribute)
    attribute.ends_with?("password2") ||
      attribute.ends_with?("verify")
  end
end

require "spec_helper"

describe MiqProductFeature do
  before do
    @expected_feature_count = 858
  end

  context ".seed" do
    it "expected feature count with no duplicate identifiers" do
      seeded_identifiers = MiqProductFeature.seed
      expect(MiqProductFeature.count).to eq(@expected_feature_count)
      expect(seeded_identifiers).to match_array seeded_identifiers.uniq
    end

    it "run twice" do
      MiqProductFeature.seed
      MiqProductFeature.seed
      MiqProductFeature.count.should eq(@expected_feature_count)
    end

    it "with existing records" do
      deleted   = FactoryGirl.create(:miq_product_feature, :identifier => "xxx")
      changed   = FactoryGirl.create(:miq_product_feature, :identifier => "about", :name => "XXX")
      unchanged = FactoryGirl.create(:miq_product_feature_everything)
      unchanged_orig_updated_at = unchanged.updated_at

      MiqProductFeature.seed
      MiqProductFeature.count.should eq(@expected_feature_count)
      expect { deleted.reload }.to raise_error(ActiveRecord::RecordNotFound)
      changed.reload.name.should == "About"
      unchanged.reload.updated_at.should be_same_time_as unchanged_orig_updated_at
    end
  end
end

require "spec_helper"
include AutomationSpecHelper

describe TreeBuilderAeClass do
  context "initialize" do
    before do
      create_state_ae_model(:name => 'LUIGI', :ae_class => 'CLASS1', :ae_namespace => 'A/B/C')
      create_ae_model(:name => 'MARIO', :ae_class => 'CLASS3', :ae_namespace => 'C/D/E')
      @sb = {:trees => {:ot_tree => {:open_nodes => []}}, :active_tree => :ot_tree}
    end

    it "a tree with filter" do
      @sb[:cached_waypoint_ids] =  MiqAeClass.waypoint_ids_for_state_machines
      tree = TreeBuilderAeClass.new(:automate_tree, "automate", @sb)
      domains = JSON.parse(tree.tree_nodes).first['children'].collect { |h| h['title'] }
      domains.should match_array ['LUIGI']
    end

    it "a tree without filter" do
      tree = TreeBuilderAeClass.new(:automate_tree, "automate", @sb)
      domains = JSON.parse(tree.tree_nodes).first['children'].collect { |h| h['title'] }
      domains.should match_array %w(LUIGI MARIO)
    end
  end

  context "#x_get_tree_roots" do
    before do
      root_tenant = EvmSpecHelper.create_root_tenant
      user = FactoryGirl.create(:user)
      User.stub(:current_user).and_return(user)
      user.stub(:current_tenant).and_return(root_tenant)
      tenant2 = FactoryGirl.create(:tenant, :parent => root_tenant)
      FactoryGirl.create(:miq_ae_domain, :name => "test1", :parent => nil, :tenant => root_tenant)
      FactoryGirl.create(:miq_ae_domain, :name => "test2", :parent => nil, :tenant => root_tenant)
      FactoryGirl.create(:miq_ae_domain, :name => "test3", :parent => nil, :tenant => tenant2)
      FactoryGirl.create(:miq_ae_domain, :name => "test4", :parent => nil, :tenant => tenant2)
    end

    it "should only return domains in a user's current tenant" do
      tree = TreeBuilderAeClass.new("ae_tree", "ae", {})
      domains = JSON.parse(tree.tree_nodes).first['children'].collect { |h| h['title'] }
      domains.should match_array %w(test1 test2)
      domains.should_not include %w(test3 test4)
    end
  end
end

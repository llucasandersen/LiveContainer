//
//  VirtualWindowsHostView.m
//  LiveContainer
//
//  Created by Duy Tran on 22/2/26.
//
#import "DecoratedAppSceneViewController.h"
#import "VirtualWindowsHostView.h"

@interface VirtualWindowsHostView()
@property(nonatomic) CGRect lastLayoutBounds;
@property(nonatomic) UIEdgeInsets lastLayoutInsets;
@end

@implementation VirtualWindowsHostView
- (instancetype)init {
    self = [super initWithFrame:CGRectZero];
    self.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.shouldForwardTapAction = YES;
    return self;
}

- (void)didMoveToSuperview {
    [super didMoveToSuperview];
    if (self.superview) {
        self.frame = self.superview.bounds;
    }
}

- (void)safeAreaInsetsDidChange {
    [super safeAreaInsetsDidChange];
    [self setNeedsLayout];
}

- (void)layoutSubviews {
    [super layoutSubviews];
    if (!self.window || (CGRectEqualToRect(self.lastLayoutBounds, self.bounds) &&
        UIEdgeInsetsEqualToEdgeInsets(self.lastLayoutInsets, self.safeAreaInsets))) {
        return;
    }
    self.lastLayoutBounds = self.bounds;
    self.lastLayoutInsets = self.safeAreaInsets;
    // A fold can resize the host without changing orientation. Reflow each
    // guest against its own host window, including maximized virtual windows.
    for (UIView *view in self.subviews) {
        DecoratedAppSceneViewController *controller = (id)view._viewDelegate;
        if (![controller isKindOfClass:DecoratedAppSceneViewController.class] ||
            !controller.appSceneVC.presenter.scene) {
            continue;
        }
        [controller appSceneVC:controller.appSceneVC
         didUpdateFromSettings:controller.appSceneVC.presenter.scene.settings.mutableCopy
             transitionContext:nil lifecycleActionType:0];
    }
}
- (BOOL)handleStatusBarTapAction:(UIAction *)action {
    if(!self.shouldForwardTapAction) return NO;
    // grab the frontmost app window, if it's visible pass this event to it
    UIView *frontmostView = self.subviews.lastObject;
    if(!frontmostView.hidden) {
        DecoratedAppSceneViewController *decoratedVC = (id)frontmostView._viewDelegate;
        [decoratedVC.appSceneVC handleStatusBarTapAction:action];
    }
    return !frontmostView.hidden;
}
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView* hitView = [super hitTest:point withEvent:event];
    if(hitView == self) {
        self.shouldForwardTapAction = NO;
        return nil;
    } else {
        self.shouldForwardTapAction = YES;
        return hitView;
    }
}
@end
